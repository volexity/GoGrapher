use std::{
    borrow::Borrow,
    collections::HashMap,
    path::{Path, PathBuf},
    thread,
    time::Duration
};

use object::{File, Object, ObjectSymbol, Symbol};
use pyo3::{
    pyclass,
    pymethods,
    PyRef,
    PyResult,
    Python,
    exceptions::PyKeyboardInterrupt};
use rand::seq::index::{sample, IndexVec};
use regex::Regex;
use smda::{function::Instruction, report::DisassemblyReport, Disassembler};

use crate::{control_flow_graph::{BasicBlock, ControlFlowGraph}, error::Error};

/// Data Model of a disassembled binary.
#[pyclass]
#[derive(Clone)]
pub struct Disassembly {
    #[pyo3(get)]
    pub(crate) name: String,
    #[pyo3(get)]
    pub(crate) path: PathBuf,
    #[pyo3(get)]
    pub(crate) graphs: Vec<ControlFlowGraph>,
}

impl Disassembly {
    // TODO: Some of these `expects` should be returned as results...
    /// Generate the set of Control Flow Graphs (CFG) for the specified binary.
    pub fn new(sample_path: &Path) -> Result<Self, Error> {
        let file_name = sample_path
            .file_name()
            .expect("Sample has no file name")
            .to_string_lossy();
        let sample_data = std::fs::read(sample_path).expect("Could not read sample data");
        let parsed_sample = File::parse(&*sample_data).expect("Could not parse sample data");
        // Build the hashmap of the symbols for fast access.
        let mut graph_symbols: HashMap<u64, Symbol> = HashMap::new();
        for symbol in parsed_sample.symbols() {
            graph_symbols.insert(symbol.address(), symbol);
        }

        let sample_dissassembly_result: Result<DisassemblyReport, smda::Error> = Disassembler::disassemble_file(
            &sample_path.to_string_lossy(),
            true,
            true,
            Some(&sample_data),
        );
        
        match sample_dissassembly_result {
            Err(error) => match error {
                smda::Error::UnsupportedFormatError => {
                    Err(Error::UnsupportedBinaryFormat {
                        sample: sample_path.to_string_lossy().to_string(),
                    })
                },
                _ => panic!("Failed to disassemble sample"),
            },
            Ok(sample_dissassembly) => {
                // Convert each smda_function to a ControlFlowGraph.
                let smda_functions = sample_dissassembly
                    .get_functions()
                    .expect("Failed to get functions");

                let mut graphs: Vec<ControlFlowGraph> = Vec::with_capacity(smda_functions.len());
                for (fct_offset, function) in smda_functions {
                    let symbol_name: &str = if graph_symbols.contains_key(fct_offset) {
                        graph_symbols[fct_offset]
                            .name()
                            .expect("Failed to get symbol name")
                    } else {
                        ""
                    };

                    // Convert each smda_block to a basic block.
                    let mut blocks: Vec<BasicBlock> = Vec::new();
                    let smda_blocks: &HashMap<u64, Vec<Instruction>> =
                        function.get_blocks().expect("Failed to get blocks");
                    for (block_offset, instructions) in smda_blocks {
                        let block = BasicBlock::new(*block_offset, instructions);
                        blocks.push(block);
                    }
                    blocks.sort_by_key(|a| a.offset);

                    // Pre-compute the block indices.
                    let mut block_indices: HashMap<u64, usize> = HashMap::new();
                    for (index, block) in blocks.iter().enumerate() {
                        block_indices.insert(block.offset, index);
                    }

                    // Resolve the incomming and outgoing edges.
                    for (offset, out_refs) in &function.blockrefs {
                        let block_index: usize = *block_indices
                            .get(offset)
                            .expect("Failed to get block for offset");

                        for out_ref in out_refs {
                            let out_index: usize = *block_indices.get(out_ref).expect("Invalid block ref");
                            blocks[block_index].out_refs.push(out_index);
                            blocks[out_index].in_refs.push(block_index);
                        }
                    }
                    // Sorts the block list by offsets.
                    let graph = ControlFlowGraph::new(symbol_name, *fct_offset, blocks);
                    graphs.push(graph);
                }

                // Sorts the final list by offsets.
                graphs.sort_by_key(|a| a.offset);

                Ok(Disassembly {
                    name: file_name.to_string(),
                    path: sample_path.to_path_buf(),
                    graphs,
                })
            },
        }
    }

    /// Name of the disassembled binary.
    #[inline]
    pub fn name(&self) -> &String {
        &self.name
    }

    /// Path to the disassembled binary.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Array of the Control Flow Graphs (CFG) of the binary.
    #[inline]
    pub fn graphs(&self) -> &Vec<ControlFlowGraph> {
        &self.graphs
    }

    /// Returns a new Disassembly composed of the Control Flow Graphs (CFG) whose name match the supplied regex.
    pub fn filter_symbol(&self, search_expression: &str) -> Self {
        let regex_exp: Regex = Regex::new(search_expression).expect("Failed to create regex");

        Self {
            name: self.name.clone(),
            path: self.path.clone(),
            graphs: self
                .graphs
                .iter()
                .filter(|&graph| regex_exp.is_match(&graph.name))
                .cloned()
                .collect(),
        }
    }

    /// Returns a subset of the disassembly corresponding to the supplied ratio.
    pub fn to_subset(&self, ratio: f32) -> Self {
        let n_args: usize = (self.graphs.len() as f32 * ratio.clamp(0.0, 1.0)) as usize;
        let subset_indices: IndexVec = sample(&mut rand::thread_rng(), self.graphs.len(), n_args);

        Self {
            name: self.name.clone(),
            path: self.path.clone(),
            graphs: subset_indices
                .iter()
                .map(|index| self.graphs[index].clone())
                .collect(),
        }
    }
}

#[pymethods]
impl Disassembly {
    #[new]
    fn py_new(sample_path: PathBuf, py: Python) -> PyResult<Self> {
        let thread_handle: thread::JoinHandle<Result<Self, Error>> = thread::spawn(move || {
            Disassembly::new(&sample_path)
        });

        loop {
            if py.check_signals().is_err() {
                break Err(
                    PyKeyboardInterrupt::new_err("Rust: received ctrl-c.")
                );
            }
            if thread_handle.is_finished() {
                break Ok(thread_handle.join().unwrap()?);
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[pyo3(name = "filter_symbol")]
    fn filter_symbol_py(&self, search_expression: String) -> Self {
        self.filter_symbol(search_expression.as_str())
    }

    #[pyo3(name = "get_subset")]
    fn get_subset_py(&self, ratio: f32) -> Self {
        self.to_subset(ratio)
    }
}

impl Borrow<Disassembly> for PyRef<'_, Disassembly> {
    fn borrow(&self) -> &Disassembly {
        self
    }
}
