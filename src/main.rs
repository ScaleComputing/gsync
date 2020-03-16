use jane_eyre::ErrReport;
use tracing_error::ErrorLayer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

fn main() -> Result<(), ErrReport> {
    color_backtrace::install();

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    let subscriber = Registry::default().with(filter).with(ErrorLayer::default());

    tracing::subscriber::set_global_default(subscriber).expect("Could not set global default");

    color_backtrace::install();

    gsync::lib_main()?;

    Ok(())
}
