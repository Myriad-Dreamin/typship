use clap::Subcommand;

pub mod check;
pub mod clean;
pub mod dev;
pub mod download;
pub mod exclude;
pub mod init;
pub mod install;
pub mod login;
pub mod package;
pub mod publish;

#[derive(Subcommand)]
pub enum Commands {
    #[command(name = "package", alias = "pkg")]
    #[command(subcommand)]
    Package(package::PackageCommands),
    Check(check::CheckArgs),
    Clean(clean::CleanArgs),
    Dev(dev::DevArgs),
    Download(download::DownloadArgs),
    Exclude(exclude::ExcludeArgs),
    Init(init::InitArgs),
    Install(install::InstallArgs),
    Login(login::LoginArgs),
    Publish(publish::PublishArgs),
}
