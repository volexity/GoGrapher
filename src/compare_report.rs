use std::time::Duration;

use pyo3::{pyclass, pymethods};
use serde::{Deserialize, Serialize};

use crate::r#match::Binary as BinaryMatch;

/// GoGrapher compare report data model.
#[pyclass]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompareReport {
    #[pyo3(get)]
    sample_name: String,
    #[pyo3(get)]
    matches: Vec<BinaryMatch>,
    compute_time: Duration,
}

impl CompareReport {
    /// Create a new instance of the CompareReport data model.
    pub fn new(
        sample_name: &str,
        matches: Vec<BinaryMatch>,
        compute_time: Duration,
    ) -> Self {
        Self {
            sample_name: sample_name.to_string(),
            matches,
            compute_time,
        }
    }

    /// The name of the sample this report belongs to.
    #[inline]
    pub fn sample_name(&self) -> &String {
        &self.sample_name
    }

    /// The set of match results per GO version.
    #[inline]
    pub fn matches(&self) -> &Vec<BinaryMatch> {
        &self.matches
    }

    /// How long did the compute take.
    #[inline]
    pub fn compute_time(&self) -> &Duration {
        &self.compute_time
    }

    /// Returns the JSON representation the the compare report.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("Failed to serialize")
    }

    /// Parse a CompareReport from its JSON representation.
    pub fn from_json(json_data: &str) -> Self {
        serde_json::from_str(json_data).expect("Failed to deserialize")
    }
}

#[pymethods]
impl CompareReport {
    #[pyo3(name = "to_json")]
    fn py_to_json(&self) -> String {
        self.to_json()
    }

    #[staticmethod]
    #[pyo3(name = "from_json")]
    fn py_from_json(json_data: &str) -> Self {
        CompareReport::from_json(json_data)
    }
}
