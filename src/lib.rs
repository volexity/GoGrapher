/* GoGrapher library definition. */

use pyo3::{
    pymodule,
    types::{PyModule, PyModuleMethods},
    Bound, PyResult,
};

pub use self::cli::Cli;
pub use self::compare_report::CompareReport;
pub use self::control_flow_graph::{BasicBlock, ControlFlowGraph};
pub use self::disassembly::Disassembly;
pub use self::error::Error;
pub use self::grapher::Grapher;
pub use self::r#match::{Binary as BinaryMatch, Method as MethodMatch};

mod cli;
mod compare_report;
mod control_flow_graph;
mod disassembly;
mod error;
mod grapher;
mod r#match;

// Python entrypoint
#[pymodule]
fn gographer(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<MethodMatch>()?;
    module.add_class::<BinaryMatch>()?;
    module.add_class::<ControlFlowGraph>()?;
    module.add_class::<Disassembly>()?;
    module.add_class::<CompareReport>()?;
    module.add_class::<Grapher>()?;
    module.add_class::<Cli>()?;
    module.add_class::<self::error::PyUnsupportedBinaryFormat>()?;

    Ok(())
}
