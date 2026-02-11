# fuse-access-guard

FUSE ベースのファイルアクセス制限ラッパー。`.claude/settings.json` の deny ルールに基づき、Linux のマウント名前空間と FUSE パススルーファイルシステムを使って、指定ファイルへのアクセスをカーネルレベルでブロックします。

root 権限は不要です（ユーザー名前空間を利用）。

## 動作要件

| 要件 | 詳細 |
|------|------|
| OS | Linux (kernel 4.18+) |
| FUSE 3 | `libfuse3-dev` (Debian/Ubuntu) / `fuse3-devel` (Fedora/RHEL) |
| ユーザー名前空間 | `sysctl kernel.unprivileged_userns_clone=1` |
| Rust | 1.70+ |

```bash
# Debian/Ubuntu
sudo apt install fuse3 libfuse3-dev
```

## インストール

```bash
cargo install --path .
```

またはソースからビルド:

```bash
cargo build --release
# バイナリ: target/release/fuse-access-guard
```

## 使い方

```bash
fuse-access-guard [OPTIONS] -- COMMAND [ARGS...]
```

### オプション

| オプション | 説明 |
|-----------|------|
| `-q`, `--quiet` | stderr への DENIED ログ出力を抑制 |
| `--log-file <PATH>` | アクセス拒否ログをファイルに書き出す |

### 使用例

```bash
# 秘密ファイルへの読み取りをブロック
fuse-access-guard -- cat .env
# => cat: .env: Permission denied

# 許可されたファイルはそのまま読める
fuse-access-guard -- cat README.md
# => (ファイル内容がそのまま表示される)

# シェル経由でも子プロセスに制限が継承される
fuse-access-guard -- bash -c "cat .env"
# => cat: .env: Permission denied

# quiet モード + ログファイル出力
fuse-access-guard --quiet --log-file /tmp/access.log -- make build
```

## 設定

作業ディレクトリに `.claude/settings.json` を作成:

```json
{
  "permissions": {
    "deny": [
      "Read(./.env)",
      "Read(./credentials.json)",
      "Write(./config/*.secret)",
      "Read(./*.pem)"
    ]
  }
}
```

### deny ルールの書式

```
Operation(path)
```

| 項目 | 値 | 例 |
|------|-----|-----|
| Operation | `Read`, `Write`, `Execute` | `Read(./file)` |
| パス (相対) | `./` で始まる (cwd 基準) | `Read(./secret.txt)` |
| パス (絶対) | `/` で始まる | `Read(/etc/shadow)` |
| glob | `*`, `?`, `[...]` | `Read(./*.pem)`, `Write(./config/*.secret)` |

glob パターンはドットファイル (`.env` 等) にもマッチします。

## アーキテクチャ

### プロセスモデル (二重 fork)

```
Parent process
  │
  ├─ fork() ──► Child A (FUSE daemon)
  │               │
  │               ├─ unshare(CLONE_NEWUSER | CLONE_NEWNS)
  │               ├─ uid/gid マッピング設定
  │               ├─ マウント伝播を private に設定
  │               ├─ pipe 作成 (同期用)
  │               ├─ ソースディレクトリの fd を事前に open
  │               │
  │               ├─ fork() ──► Child B (コマンド実行)
  │               │               │
  │               │               ├─ pipe で FUSE マウント完了を待機
  │               │               ├─ cwd 再解決 (chdir "/" → chdir cwd)
  │               │               └─ execvp(command)
  │               │
  │               ├─ FUSE パススルー FS をマウント (spawn_mount2)
  │               ├─ pipe で Child B にシグナル送信
  │               ├─ waitpid(Child B)
  │               └─ FUSE アンマウント & exit
  │
  └─ waitpid(Child A) → 終了コードを伝播
```

### 処理の流れ

1. `.claude/settings.json` から deny ルールを読み込み
2. deny 対象パスの親ディレクトリを集約し、マウントポイントを算出
3. `fork()` → Child A でユーザー名前空間 + マウント名前空間を作成
4. Child A: 2回目の `fork()` → Child B を生成 (FUSE スレッド生成前に fork する必要がある)
5. Child A: deny 対象ディレクトリの fd を `open()` で取得 (FUSE マウント前にバイパス用)
6. Child A: FUSE パススルー FS を対象ディレクトリにマウント
7. Child A: pipe 経由で Child B に「マウント完了」を通知
8. Child B: cwd を再解決し (カーネルの dentry キャッシュをフラッシュ)、コマンドを `execvp()`
9. FUSE が `open()` をインターセプトし、deny ルールに該当すれば `EACCES` を返す
10. 全子プロセスがマウント名前空間を継承するため、制限を回避できない

### 主な技術的ポイント

| 課題 | 解決策 |
|------|--------|
| root 権限なしで名前空間を作成 | `CLONE_NEWUSER` で uid/gid マッピングを設定 |
| fork 後に FUSE スレッドが消える | FUSE スレッド生成 **前** に fork し、pipe で同期 |
| FUSE デーモンが実ファイルにアクセスできない | マウント前に `open()` した fd を `openat()` で利用 |
| cwd が FUSE マウントをバイパスする | `chdir("/")` → `chdir(cwd)` で dentry キャッシュを再解決 |

## モジュール構成

```
src/
├── main.rs            # エントリポイント。モジュール統合
├── cli.rs             # コマンドライン引数パーサー (clap derive)
├── config.rs          # .claude/settings.json の読み込み
├── rules.rs           # アクセスルールエンジン (Operation, DenyRule, glob マッチ)
├── logger.rs          # アクセス拒否ログ出力 (stderr / ファイル)
├── namespace.rs       # マウント名前空間管理 (fork, unshare, FUSE マウント)
└── passthrough_fs.rs  # FUSE パススルーファイルシステム (openat ベース)
```

### 各モジュールの概要

**`cli.rs`** - clap の derive マクロで CLI 引数を定義。`--quiet`, `--log-file`, `-- COMMAND [ARGS...]` をパース。

**`config.rs`** - 作業ディレクトリの `.claude/settings.json` を serde_json でデシリアライズ。`Settings > Permissions > deny: Vec<String>` の構造。

**`rules.rs`** - deny ルール文字列 (`"Read(./path)"`) をパースし、`AccessRules` を構築。`is_denied(path, operation)` で拒否判定。glob パターンは `glob::MatchOptions { require_literal_leading_dot: false }` でドットファイルにもマッチ。

**`logger.rs`** - 拒否イベントを `[DENIED] {timestamp} pid={pid} proc={name} op={op} path={path}` 形式で出力。外部クレートに依存しない UTC タイムスタンプ生成。

**`namespace.rs`** - 二重 fork + pipe 同期 + FUSE マウントのオーケストレーション。`compute_mount_points()` で deny ルールからマウントポイントを算出。

**`passthrough_fs.rs`** - `fuser::Filesystem` トレイトを実装した FUSE パススルー FS。FUSE マウント前に開いた fd を `openat()`, `fstatat()`, `pread()`, `pwrite()` 等の libc 関数で利用し、自身のマウントをバイパスして実ファイルにアクセス。`open()` / `access()` 時に `AccessRules` をチェックし、拒否対象なら `EACCES` を返す。

## テスト

```bash
# ユニットテストのみ
cargo test

# E2E テストを含む全テスト (FUSE + ユーザー名前空間が必要)
cargo test -- --include-ignored
```

### テスト構成

- **ユニットテスト (20件)**: `cli`, `config`, `rules`, `logger` の各モジュールに内蔵
- **E2E テスト (5件)**: `tests/e2e_test.rs`
  - `test_deny_read_blocked` - deny ルール対象ファイルの読み取りがブロックされる
  - `test_allowed_read_passes` - 許可されたファイルは正常に読める
  - `test_child_process_also_blocked` - bash 経由の子プロセスにも制限が継承される
  - `test_quiet_flag_suppresses_output` - `--quiet` で stderr の DENIED ログが抑制される
  - `test_no_mount_points_direct_execution` - マウント不要時は直接実行にフォールバック

E2E テストは FUSE 3 とユーザー名前空間のサポートが必要なため、`#[ignore]` が付与されています。CI 環境では `--include-ignored` を明示的に指定してください。

## ログ出力

アクセスが拒否されると、以下の形式でログが出力されます:

```
[DENIED] 2026-02-11T15:05:12Z pid=12345 proc=cat op=read path=/home/user/.env
```

`--quiet` オプションで stderr 出力を抑制し、`--log-file` でファイルに記録できます。

## 依存クレート

| クレート | バージョン | 用途 |
|---------|-----------|------|
| `clap` | 4 | CLI 引数パーサー (derive) |
| `fuser` | 0.15 | FUSE ファイルシステム実装 |
| `glob` | 0.3 | glob パターンマッチ |
| `nix` | 0.29 | Unix システムコール (fork, unshare, mount 等) |
| `serde` / `serde_json` | 1 | JSON デシリアライズ |
| `libc` | 0.2 | 低レベル C ライブラリ (openat, fstatat 等) |
| `thiserror` | 2 | エラー型の derive マクロ |
| `tempfile` | 3 | テスト用一時ディレクトリ (dev-dependency) |

## ライセンス

MIT
