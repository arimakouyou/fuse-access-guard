use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyStatfs, ReplyWrite, Request,
};

use crate::logger::Logger;
use crate::rules::{AccessRules, Operation};

const TTL: Duration = Duration::from_secs(1);

pub struct PassthroughFs {
    /// The original source directory path (for deny rule matching)
    source_dir: PathBuf,
    /// Raw fd of the source directory opened BEFORE FUSE mount.
    /// Used with openat/fstatat to bypass the FUSE mount.
    source_fd: RawFd,
    /// Keep the File alive so fd remains valid
    _source_file: std::fs::File,
    /// Inode -> relative path from source_dir (for openat)
    inodes: HashMap<u64, PathBuf>,
    path_to_inode: HashMap<PathBuf, u64>,
    next_inode: u64,
    /// File handle -> (raw fd, virtual path)
    file_handles: HashMap<u64, (RawFd, PathBuf)>,
    next_fh: u64,
    rules: Arc<AccessRules>,
    logger: Arc<Mutex<Logger>>,
}

impl PassthroughFs {
    pub fn new(
        source_dir: PathBuf,
        source_file: std::fs::File,
        rules: Arc<AccessRules>,
        logger: Arc<Mutex<Logger>>,
    ) -> Self {
        let source_fd = source_file.as_raw_fd();

        let mut inodes = HashMap::new();
        let mut path_to_inode = HashMap::new();
        // Root inode (1) maps to "" (empty relative path = source dir itself)
        let root_rel = PathBuf::from("");
        inodes.insert(1, root_rel.clone());
        path_to_inode.insert(root_rel, 1);

        PassthroughFs {
            source_dir,
            source_fd,
            _source_file: source_file,
            inodes,
            path_to_inode,
            next_inode: 2,
            file_handles: HashMap::new(),
            next_fh: 1,
            rules,
            logger,
        }
    }

    fn get_or_create_inode(&mut self, rel_path: &Path) -> u64 {
        if let Some(&ino) = self.path_to_inode.get(rel_path) {
            return ino;
        }
        let ino = self.next_inode;
        self.next_inode += 1;
        self.inodes.insert(ino, rel_path.to_path_buf());
        self.path_to_inode.insert(rel_path.to_path_buf(), ino);
        ino
    }

    /// Get relative path for an inode
    fn rel_path(&self, ino: u64) -> Option<&PathBuf> {
        self.inodes.get(&ino)
    }

    /// Get the virtual (absolute) path for deny rule matching
    fn virtual_path(&self, ino: u64) -> Option<PathBuf> {
        self.rel_path(ino)
            .map(|rel| self.source_dir.join(rel))
    }

    /// fstatat on the source_fd with the given relative path
    fn stat_relative(&self, rel: &Path) -> Result<libc::stat, i32> {
        let c_path = path_to_cstring(rel);
        unsafe {
            let mut stat: libc::stat = std::mem::zeroed();
            let flags = libc::AT_SYMLINK_NOFOLLOW;
            let ret = libc::fstatat(self.source_fd, c_path.as_ptr(), &mut stat, flags);
            if ret == 0 {
                Ok(stat)
            } else {
                Err(*libc::__errno_location())
            }
        }
    }

    /// openat on the source_fd
    fn open_relative(&self, rel: &Path, flags: libc::c_int) -> Result<RawFd, i32> {
        let c_path = path_to_cstring(rel);
        unsafe {
            let fd = libc::openat(self.source_fd, c_path.as_ptr(), flags);
            if fd >= 0 {
                Ok(fd)
            } else {
                Err(*libc::__errno_location())
            }
        }
    }

    fn flags_to_operation(flags: i32) -> Operation {
        let access_mode = flags & libc::O_ACCMODE;
        match access_mode {
            libc::O_RDONLY => Operation::Read,
            libc::O_WRONLY | libc::O_RDWR => Operation::Write,
            _ => Operation::Read,
        }
    }

    fn get_caller_executable(pid: u32) -> Option<PathBuf> {
        let path = format!("/proc/{}/exe", pid);
        std::fs::read_link(path).ok()
    }
}

fn path_to_cstring(path: &Path) -> CString {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() {
        // Empty path = current directory reference for *at() syscalls
        CString::new(".").unwrap()
    } else {
        CString::new(bytes).unwrap_or_else(|_| CString::new(".").unwrap())
    }
}

fn stat_to_attr(ino: u64, stat: &libc::stat) -> FileAttr {
    let kind = match stat.st_mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        _ => FileType::RegularFile,
    };

    FileAttr {
        ino,
        size: stat.st_size as u64,
        blocks: stat.st_blocks as u64,
        atime: UNIX_EPOCH + Duration::from_secs(stat.st_atime as u64),
        mtime: UNIX_EPOCH + Duration::from_secs(stat.st_mtime as u64),
        ctime: UNIX_EPOCH + Duration::from_secs(stat.st_ctime as u64),
        crtime: SystemTime::UNIX_EPOCH,
        kind,
        perm: (stat.st_mode & 0o7777) as u16,
        nlink: stat.st_nlink as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        rdev: stat.st_rdev as u32,
        blksize: stat.st_blksize as u32,
        flags: 0,
    }
}

impl Filesystem for PassthroughFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_rel = match self.rel_path(parent) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let child_rel = parent_rel.join(name);

        match self.stat_relative(&child_rel) {
            Ok(stat) => {
                let ino = self.get_or_create_inode(&child_rel);
                let attr = stat_to_attr(ino, &stat);
                reply.entry(&TTL, &attr, 0);
            }
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let rel = match self.rel_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match self.stat_relative(&rel) {
            Ok(stat) => {
                let attr = stat_to_attr(ino, &stat);
                reply.attr(&TTL, &attr);
            }
            Err(e) => reply.error(e),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let rel = match self.rel_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let virtual_p = self.source_dir.join(&rel);
        let op = Self::flags_to_operation(flags);

        // Check if executable is excluded
        let excluded = if let Some(exe) = Self::get_caller_executable(_req.pid()) {
             self.rules.is_executable_excluded(&exe)
        } else {
             false
        };

        // Check access rules
        if !excluded && self.rules.is_denied(&virtual_p, op) {
            if let Ok(mut logger) = self.logger.lock() {
                logger.log_denied(
                    _req.pid(),
                    &format!("pid:{}", _req.pid()),
                    &virtual_p.to_string_lossy(),
                    op,
                );
            }
            reply.error(libc::EACCES);
            return;
        }

        // Open the real file using openat (bypasses FUSE mount)
        let open_flags = flags & (libc::O_ACCMODE | libc::O_APPEND | libc::O_NONBLOCK);
        match self.open_relative(&rel, open_flags) {
            Ok(fd) => {
                let fh = self.next_fh;
                self.next_fh += 1;
                self.file_handles.insert(fh, (fd, virtual_p));
                reply.opened(fh, 0);
            }
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let fd = match self.file_handles.get(&fh) {
            Some((fd, _)) => *fd,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        let mut buf = vec![0u8; size as usize];
        let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, size as usize, offset) };
        if n >= 0 {
            buf.truncate(n as usize);
            reply.data(&buf);
        } else {
            reply.error(unsafe { *libc::__errno_location() });
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let fd = match self.file_handles.get(&fh) {
            Some((fd, _)) => *fd,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        let n = unsafe { libc::pwrite(fd, data.as_ptr() as *const libc::c_void, data.len(), offset) };
        if n >= 0 {
            reply.written(n as u32);
        } else {
            reply.error(unsafe { *libc::__errno_location() });
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Some((fd, _)) = self.file_handles.remove(&fh) {
            unsafe { libc::close(fd) };
        }
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let rel = match self.rel_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Open directory via openat
        let dir_fd = match self.open_relative(&rel, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(fd) => fd,
            Err(e) => {
                reply.error(e);
                return;
            }
        };

        // Use fdopendir to read directory entries
        let dirp = unsafe { libc::fdopendir(dir_fd) };
        if dirp.is_null() {
            unsafe { libc::close(dir_fd) };
            reply.error(libc::EIO);
            return;
        }

        let mut entries: Vec<(u64, FileType, String)> = Vec::new();
        entries.push((ino, FileType::Directory, ".".to_string()));
        entries.push((if ino == 1 { 1 } else { ino }, FileType::Directory, "..".to_string()));

        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                break;
            }

            let d_name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let name = d_name.to_string_lossy().to_string();
            if name == "." || name == ".." {
                continue;
            }

            let child_rel = rel.join(&name);
            let child_ino = self.get_or_create_inode(&child_rel);

            let d_type = unsafe { (*entry).d_type };
            let file_type = match d_type {
                libc::DT_DIR => FileType::Directory,
                libc::DT_LNK => FileType::Symlink,
                _ => FileType::RegularFile,
            };

            entries.push((child_ino, file_type, name));
        }

        unsafe { libc::closedir(dirp) };

        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let rel = match self.rel_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let c_path = path_to_cstring(&rel);
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let n = unsafe {
            libc::readlinkat(
                self.source_fd,
                c_path.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if n >= 0 {
            buf.truncate(n as usize);
            reply.data(&buf);
        } else {
            reply.error(unsafe { *libc::__errno_location() });
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        unsafe {
            let mut stat: libc::statfs = std::mem::zeroed();
            if libc::fstatfs(self.source_fd, &mut stat) == 0 {
                reply.statfs(
                    stat.f_blocks,
                    stat.f_bfree,
                    stat.f_bavail,
                    stat.f_files,
                    stat.f_ffree,
                    stat.f_bsize as u32,
                    stat.f_namelen as u32,
                    stat.f_frsize as u32,
                );
            } else {
                reply.error(libc::EIO);
            }
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let rel = match self.rel_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Verify directory exists via fstatat
        match self.stat_relative(&rel) {
            Ok(stat) if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR => {
                reply.opened(0, 0);
            }
            _ => reply.error(libc::ENOENT),
        }
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        let virtual_p = match self.virtual_path(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Check if executable is excluded
        let excluded = if let Some(exe) = Self::get_caller_executable(_req.pid()) {
             self.rules.is_executable_excluded(&exe)
        } else {
             false
        };

        if !excluded {
            // Check deny rules
            if mask & libc::R_OK != 0 && self.rules.is_denied(&virtual_p, Operation::Read) {
                reply.error(libc::EACCES);
                return;
            }
            if mask & libc::W_OK != 0 && self.rules.is_denied(&virtual_p, Operation::Write) {
                reply.error(libc::EACCES);
                return;
            }
            if mask & libc::X_OK != 0 && self.rules.is_denied(&virtual_p, Operation::Execute) {
                reply.error(libc::EACCES);
                return;
            }
        }

        // Check real filesystem access via faccessat
        let rel = match self.rel_path(ino) {
            Some(p) => p.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let c_path = path_to_cstring(&rel);
        let ret = unsafe { libc::faccessat(self.source_fd, c_path.as_ptr(), mask, 0) };
        if ret == 0 {
            reply.ok();
        } else {
            reply.error(unsafe { *libc::__errno_location() });
        }
    }
}

impl Drop for PassthroughFs {
    fn drop(&mut self) {
        // Close all open file handles
        for (_, (fd, _)) in self.file_handles.drain() {
            unsafe { libc::close(fd) };
        }
    }
}
