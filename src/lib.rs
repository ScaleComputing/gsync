//! git sync cli tool

use color_eyre::{Help, Report};
use eyre::{ensure, eyre, format_err};
use fs2::FileExt;
use once_cell::sync::Lazy;
use shells::wrap_bash;
use spandoc::spandoc;
use std::{
    env, fmt, fs,
    fs::File,
    path::{Path, PathBuf},
    process::Command,
};
use structopt::{
    clap::{AppSettings, Shell},
    StructOpt,
};
use tracing::{info, instrument, span, Level};

#[derive(Debug)]
pub struct RemotePath(PathBuf);

#[derive(Debug)]
pub struct RemoteRoot(&'static str);

#[derive(Debug)]
pub struct Buildvm(&'static str);

impl Buildvm {
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl RemotePath {
    pub fn display(&self) -> impl fmt::Display + '_ {
        self.0.display()
    }
}

impl RemoteRoot {
    #[instrument]
    pub fn join(self, local_path: &Path) -> Result<RemotePath, Report> {
        Ok(RemotePath(
            Path::new(self.0).join(
                local_path
                    .file_name()
                    .ok_or_else(|| eyre!("local path doesn't contain a filename"))?,
            ),
        ))
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

pub fn gsync_root() -> RemoteRoot {
    RemoteRoot(gsync_root_str())
}

fn gsync_root_str() -> &'static str {
    static GSYNC_ROOT: Lazy<String> =
        Lazy::new(|| env::var("GSYNC_ROOT").unwrap_or_else(|_| String::from("/local")));

    &*GSYNC_ROOT
}

pub fn gsync_host() -> Buildvm {
    Buildvm(gsync_host_str())
}

fn gsync_host_str() -> &'static str {
    static GSYNC_HOST: Lazy<String> =
        Lazy::new(|| env::var("GSYNC_HOST").unwrap_or_else(|_| String::from("buildvm")));

    &*GSYNC_HOST
}

/// Helper macro to enter spans conveniently
macro_rules! spanned {
    ($local:ident) => {
        let span = span!(Level::INFO, stringify!($local), $local);
        let _guard = span.enter();
    };
    (?$local:ident) => {
        let span = span!(Level::INFO, stringify!($local), ?$local);
        let _guard = span.enter();
    };
    (%$local:ident) => {
        let span = span!(Level::INFO, stringify!($local), %$local);
        let _guard = span.enter();
    };
    ($level:expr, $local:ident) => {
        let span = span!($level, stringify!($local), $local);
        let _guard = span.enter();
    };
    ($level:expr, ?$local:ident) => {
        let span = span!($level, stringify!($local), ?$local);
        let _guard = span.enter();
    };
    ($level:expr, %$local:ident) => {
        let span = span!($level, stringify!($local), %$local);
        let _guard = span.enter();
    };
    ( $( $span:tt )* ) => {
        let span = span!($($span)*);
        let _guard = span.enter();
    };
}

macro_rules! ibash {
    ( $( $cmd:tt )* ) => {{
        $crate::execute_interactive_with("bash", &format!($( $cmd )*))
    }};
}

/// Error handling wrapper macro for shells::wrap_bash
macro_rules! wrap_bash {
    ( $( $cmd:tt )* ) => {{
        let cmd = format!($( $cmd )*);
        spanned!(tracing::Level::DEBUG, %cmd);
        shells::wrap_bash!($($cmd)*)
    }}
}

fn execute_interactive_with(shell: &str, cmd: &str) -> Result<(), Report> {
    spanned!(Level::DEBUG, %cmd);

    let mut command = {
        let mut command = Command::new(shell);
        let _ = command.arg("-c").arg(cmd);
        command
    };

    let status = match command.status() {
        Ok(status) => status
            .code()
            .unwrap_or(if status.success() { 0 } else { 1 }),
        Err(_) => 126,
    };

    spanned!(?status);
    ensure!(status == 0, "Command exited with a non zero status");

    Ok(())
}

#[derive(StructOpt, Debug)]
#[structopt(
    global_settings = &[AppSettings::ColoredHelp, AppSettings::VersionlessSubcommands, AppSettings::DisableHelpSubcommand]
)]
pub struct Opt {
    /// The remote folder containing your git repos
    #[structopt(
        short = "r",
        long = "remote",
        default_value = gsync_root_str()
    )]
    remote: String,

    /// Remote host to compile on
    #[structopt(long = "host", default_value = gsync_host_str())]
    host: String,

    /// Generates a completion file
    #[structopt(
        long = "generate-completions",
        possible_values = &Shell::variants(),
    )]
    shell: Option<Shell>,

    /// Force sync to occur even if gsync believes no changes will be pushed
    #[structopt(short = "f", long = "force")]
    force: bool,

    /// In addition to syncing the root repo, recursively sync each submodule
    #[structopt(long = "sync-submodules-recursive")]
    sync_submodules: bool,

    /// Do not acquire the gsync lock prior to syncing
    #[structopt(long = "no-lock", hidden = true)]
    no_lock: bool,

    // Steamroll any changes on the remote that conflict with local changes
    #[structopt(long = "wipe-remote-changes")]
    wipe_remote_changes: bool,
}

impl Opt {
    #[spandoc]
    fn get_git_url(&self) -> color_eyre::Result<String> {
        /// Looking up url for origin
        wrap_bash!("git remote get-url origin").map_err(Into::into)
    }

    #[spandoc]
    fn cleanup_index(&self) -> color_eyre::Result<()> {
        /// Cleaning up git index
        ibash!("rm .git/index && git reset HEAD . && git status --poreclain || exit 1")
            .map_err(Into::into)
    }

    #[spandoc]
    fn remote_path(&self, git_root: &Path) -> color_eyre::Result<PathBuf> {
        /// Getting basename of git_root
        let repo_basename = git_root
            .file_name()
            .ok_or_else(|| eyre!("file has no basename component"))?;

        let remote_path = PathBuf::from(&self.remote);

        Ok(remote_path.join(repo_basename))
    }

    fn setup_remote_repo(&self, git_root: &Path, remote: &Remote) -> color_eyre::Result<()> {
        let remote_path = self.remote_path(git_root)?;

        let remote_path = {
            spanned!(?remote_path);
            remote_path
                .as_os_str()
                .to_str()
                .ok_or_else(|| eyre!("Could not parse remote_path as unicode"))?
        };

        remote.run(&format!(
            "if [ ! -d {0} ]; then
                    cd \"$(dirname {0})\"
                    echo \"Missing repo on remote, checking out clean copy\"
                    git clone \"{1}\" \"{0}\"
                else
                    exit 1
                fi",
            remote_path,
            self.get_git_url()?.trim(),
        ))?;

        Ok(())
    }

    fn sync_files(&self, sha: &str) -> color_eyre::Result<()> {
        wrap_bash!("git push -f gsync {}:refs/heads/gsync-staging", sha)
            .map(|_| ())
            .map_err(Into::into)
    }
}

struct Remote {
    host: String,
}

impl Remote {
    fn new(host: &str) -> color_eyre::Result<Self> {
        spanned!(Level::INFO, "Remote::new", host);
        let remote = Remote {
            host: host.to_owned(),
        };
        remote.run("true")?;
        Ok(remote)
    }

    #[spandoc::spandoc]
    fn run(&self, cmd: &str) -> color_eyre::Result<()> {
        spanned!(Level::INFO, "Remote::run", host = &self.host[..], cmd);

        /// Starting cmd
        let cmd = Command::new("ssh")
            .arg("-q")
            .arg("-t")
            .arg(&self.host)
            .arg(cmd)
            .status()?;

        /// Getting command exit status
        let status = cmd
            .code()
            .ok_or_else(|| format_err!("No exit status: Command interupted"))?;

        spanned!(?status);

        ensure!(status == 0, "ssh exited with a non-zero status");

        Ok(())
    }
}

/// create a temp commit containing all working changes except unstaged files and output the sha
fn get_temp_commit(local: &str) -> color_eyre::Result<String> {
    wrap_bash!(
        r#"
    set -e

    cd {}

    TEMP_INDEX=$(mktemp)

    cp .git/index $TEMP_INDEX
    GIT_INDEX_FILE=$TEMP_INDEX git add -u .
    echo "temp commit" | git commit-tree $(GIT_INDEX_FILE=$TEMP_INDEX git write-tree) -p HEAD

    rm $TEMP_INDEX"#,
        local
    )
    .map_err(Into::into)
}

fn get_git_root(start: &Path) -> color_eyre::Result<PathBuf> {
    start
        .ancestors()
        .find(|a| a.join(".git").is_dir())
        .map(Path::to_owned)
        .ok_or_else(|| eyre!("Unable to find .git/ in parent directories"))
}

fn get_git_submodules() -> Vec<PathBuf> {
    wrap_bash!("git config --file .gitmodules --get-regexp path | awk '{{ print $2 }}'")
        .unwrap_or_else(|_| String::new())
        .lines()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .collect()
}

struct GsyncLock(File);
impl GsyncLock {
    fn new() -> color_eyre::Result<Self> {
        let file = File::create("/tmp/gsync.lock")?;
        file.try_lock_exclusive()?;
        Ok(GsyncLock(file))
    }
}
impl Drop for GsyncLock {
    fn drop(&mut self) {
        self.0.unlock().expect("Failed to unlock GsyncLock");
    }
}

#[spandoc::spandoc]
pub fn run(conf: Opt) -> Result<(), Report> {
    spanned!(Level::WARN, "run", ?conf);

    let _flock = if !conf.no_lock {
        Some(GsyncLock::new())
    } else {
        None
    };

    let host = &conf.host;

    /// Establishing remote connection
    let remote = Remote::new(host)?;

    /// Getting the current directory
    let current_dir = env::current_dir()?;

    /// Finding the root of the git repository
    let git_root = get_git_root(&current_dir)
        .warning("`gsync` can only be run from within git repositories")?;

    spanned!(Level::WARN, ?git_root);

    let remote_path = conf.remote_path(&git_root)?;
    let remote_path_str = remote_path
        .as_os_str()
        .to_str()
        .ok_or_else(|| eyre!("Unable to parse remote_path as unicode"))?;

    /// Setting current directory to git_root
    env::set_current_dir(&git_root)?;

    // cleanup index.lock which occasionally gets orphaned after a git command
    let index = git_root.join(".git/index.lock");
    if index.is_file() {
        /// Removing orphaned .git/index.lock file
        fs::remove_file(&index)?;
    }

    // ensure that remote is setup, if its already been setup it will return an error so we drop
    // the return value as irrelevant
    let _ = wrap_bash!(
        "git remote set-url gsync \"ssh://{0}:{1}\" || git remote add gsync \"ssh://{0}:{1}\" 2>/dev/null",
        host,
        remote_path_str
    );

    /// Getting most recent commit
    ibash!("git --no-pager log --oneline -1").warning("The repo must have at least 1 commit")?;

    // verify index is good, or fix if not
    if ibash!("git status --short").is_err() {
        conf.cleanup_index()?;
    }

    let commit_str = git_root
        .as_os_str()
        .to_str()
        .ok_or_else(|| eyre!("Unable to parse git_root as unicode"))?;

    /// Creating a temp commit and getting its SHA
    let sha = get_temp_commit(commit_str)?;
    let sha = sha.trim();

    // 4b825dc642cb6eb9a060e54bf8d69288fbee4904 <- empty tree sha
    if conf.wipe_remote_changes {
        let remove_cmd = &format!("cd {} && git checkout -- . && git clean -df", conf.remote);

        /// Wiping remote changes
        remote.run(remove_cmd)?;
    } else if let Ok(old_sha) = std::fs::read_to_string(".git/.gsync.sha") {
        /// Getting diff between remote working directory and local temp commit
        let diff = wrap_bash!("git diff {} {}", sha, old_sha)?;

        if diff.trim().is_empty() && !conf.force {
            info!("No changes since last sync");

            // TODO remove need for scd
            /// Setting current directory back to the original directory
            env::set_current_dir(&current_dir)?;
            return Ok(());
        }
    }

    /// Syncing changes to remote
    let ret = conf.sync_files(sha);

    if ret.is_err() {
        let ret_code = conf.setup_remote_repo(&git_root, &remote);
        if ret_code.is_ok() {
            /// Retrying file sync after having cloned repo on remote
            conf.sync_files(sha)?;
        } else {
            ret?;
        }
    }

    /// Checking out temp commit on remote
    remote.run(&format!(
        r#"
            cd {} &&
                echo $USER &&
                git checkout --detach gsync-staging 2> /tmp/gsync.stderr &&
                echo "Changes synced to remote:" &&
                git --no-pager diff "HEAD@{{1}}..HEAD@{{0}}" --name-status &&
                git submodule update --init --recursive 2>> /tmp/gsync.stderr ||
                    (
                        echo Error on remote host: &&
                            cat /tmp/gsync.stderr &&
                            exit 1
                    )"#,
        remote_path_str
    ))?;

    /// Recording sha of successfully synced temp commit
    fs::write(".git/.gsync.sha", sha)?;

    if conf.sync_submodules {
        for submodule in &get_git_submodules() {
            let local = git_root.join(submodule);
            let remote = remote_path.join(submodule);
            let cmd = format!(
                "gsync --local={} --remote={} --sync-submodules-recursive --no-lock",
                local.to_string_lossy(),
                remote.to_string_lossy()
            );

            /// Syncing submodules
            ibash!("{}", cmd)?;
        }
    }

    /// Setting current directory back to the original directory
    std::env::set_current_dir(&current_dir)?;

    Ok(())
}

pub fn lib_main() -> Result<(), Report> {
    let conf = Opt::from_args();

    if let Some(shell) = conf.shell {
        Opt::clap().gen_completions_to("gsync", shell, &mut std::io::stdout());
        Ok(())
    } else {
        run(conf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_sha_ok() {
        let sha = get_temp_commit(".");
        println!("{:?}", sha);
        assert_eq!(sha.unwrap().trim().len(), 40);
    }

    #[test]
    fn get_sha_err() {
        let err = get_temp_commit("/");
        println!("{:?}", err);
        assert!(err.is_err());
    }
}
