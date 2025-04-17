use std::fmt::Debug;

use pyo3::{exceptions::PyException, pyclass, pymethods, PyErr};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("ERROR: Unsupported binary format for sample {sample:?} !")]
    UnsupportedBinaryFormat { sample: String },
}

impl From<Error> for PyErr {
    /// Implements automatic conversion of GoGrapher's error types to python.
    fn from(error: Error) -> Self {
        let message: String = error.to_string();
        match error {
            Error::UnsupportedBinaryFormat { sample } => {
                PyErr::new::<PyUnsupportedBinaryFormat, _>((message, sample))
            }
        }
    }
}

/// Python version of the UnsupportedBinaryFormat error.
#[pyclass(extends=PyException, name="UnsupportedBinaryFormat")]
pub(super) struct PyUnsupportedBinaryFormat {
    #[pyo3(get)]
    message: String,
    #[pyo3(get)]
    sample: String,
}

#[pymethods]
impl PyUnsupportedBinaryFormat {
    /// Create a new PyUnsupportedBinaryFormat instance.
    #[new]
    fn new(message: String, sample: String) -> Self {
        Self { message, sample }
    }

    /// Return the error message as its string representation.
    fn __str__(&self) -> &String {
        &self.message
    }
}
