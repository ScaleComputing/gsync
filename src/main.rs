use jane_eyre::ErrReport;

fn main() -> Result<(), ErrReport> {
    tracing_subscriber::fmt::init();
    color_backtrace::install();

    gsync::lib_main()?;

    Ok(())
}
