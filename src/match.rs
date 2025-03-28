use pyo3::pyclass;
use serde::{Deserialize, Serialize};

use crate::control_flow_graph::ControlFlowGraph;

/// Data Model of the similarity between two Control Flow Graphs (CFG) methods.
#[pyclass(name = "MethodMatch")]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Method {
    #[pyo3(get)]
    old_name: String,
    #[pyo3(get)]
    resolved_name: String,
    #[pyo3(get)]
    malware_offset: u64,
    #[pyo3(get)]
    clean_offset: u64,
    #[pyo3(get)]
    pub(crate) similarity: f32,
}

impl Method {
    /// Create a new MethodMatch instance.
    pub fn new(
        malware_graph: &ControlFlowGraph,
        clean_graph: &ControlFlowGraph,
        similarity: f32,
    ) -> Self {
        Self {
            old_name: malware_graph.name.to_string(),
            resolved_name: clean_graph.name.to_string(),
            malware_offset: malware_graph.offset,
            clean_offset: clean_graph.offset,
            similarity,
        }
    }

    /// Name of the sample method.
    #[inline]
    pub fn old_name(&self) -> &String {
        &self.old_name
    }

    /// Name of the resolved clean method.
    #[inline]
    pub fn resolved_name(&self) -> &String {
        &self.resolved_name
    }

    /// Offset of the malware method that matched.
    #[inline]
    pub fn malware_offset(&self) -> u64 {
        self.malware_offset
    }

    /// Offset of the clean method that matched.
    #[inline]
    pub fn clean_offset(&self) -> u64 {
        self.clean_offset
    }

    /// Normalized similarity ratio between the two methods.
    #[inline]
    pub fn similarity(&self) -> f32 {
        self.similarity
    }
}

/// Data Model of the similarity between the Control Flow Gaphs (CFG) of two binaries.
#[pyclass(name = "BinaryMatch")]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Binary {
    #[pyo3(get)]
    similarity: f32,
    #[pyo3(get)]
    source: String,
    #[pyo3(get)]
    dest: String,
    #[pyo3(get)]
    matches: Vec<Method>,
}

impl Binary {
    /// Create a new BinaryMatch instance.
    pub fn new(source: &str, dest: &str, matches: &[Method]) -> Self {
        Self {
            similarity: matches.iter().map(|m| m.similarity).sum::<f32>() / matches.len() as f32,
            source: source.to_string(),
            dest: dest.to_string(),
            matches: matches.to_vec(),
        }
    }

    /// Normalized similarity ratio between the two binaries.
    #[inline]
    pub fn similarity(&self) -> f32 {
        self.similarity
    }

    /// The name of the source binary during testing.
    #[inline]
    pub fn source(&self) -> &String {
        &self.source
    }

    /// The name of the destination binary during testing.
    #[inline]
    pub fn dest(&self) -> &String {
        &self.dest
    }

    /// Array of match result between methods of both binaries.
    #[inline]
    pub fn matches(&self) -> &Vec<Method> {
        &self.matches
    }
}
