use std::{
    borrow::Borrow,
    ops::Deref,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
    thread
};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use pyo3::{
    pyclass,
    pymethods,
    PyRef,
    PyResult,
    Python,
    exceptions::PyKeyboardInterrupt
};
use rayon::prelude::*;
use smda::function::Instruction;

use crate::{compare_report::CompareReport, error::Error};
use crate::control_flow_graph::{BasicBlock, ControlFlowGraph};
use crate::disassembly::Disassembly;
use crate::r#match::{Binary as BinaryMatch, Method as MethodMatch};

struct InstructionStreamer<'a> {
    blocks: &'a [BasicBlock],
    indices: &'a [usize],
}

impl<'a> InstructionStreamer<'a> {
    fn new(blocks: &'a [BasicBlock], indices: &'a [usize]) -> Self {
        Self { blocks, indices }
    }

    fn len(&self) -> usize {
        let mut count = 0;
        for i in self.indices {
            count += self.blocks[*i].instructions.len()
        }
        count
    }

    fn iter(&self) -> InstructionStreamerIter<'_> {
        InstructionStreamerIter {
            iter: None,
            indices: self.indices.iter(),
            streamer: self,
        }
    }
}

struct InstructionStreamerIter<'a> {
    iter: Option<std::slice::Iter<'a, Instruction>>,
    indices: std::slice::Iter<'a, usize>,
    streamer: &'a InstructionStreamer<'a>,
}

impl<'a> Iterator for InstructionStreamerIter<'a> {
    type Item = &'a Instruction;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(it) = self.iter.as_mut() {
            let next = it.next();
            if next.is_some() {
                return next;
            }
        }
        // NOTE: Incorrect linter warning...
        #[allow(clippy::never_loop)]
        for i in &mut self.indices {
            let mut it = self.streamer.blocks[*i].instructions.iter();
            let next = it.next();
            self.iter = Some(it);
            return next;
        }
        None
    }
}

/// Compute a summary of the similarities between a malware sample and a set of clean libraries.
#[pyclass]
#[derive(Clone)]
pub struct Grapher {
    display_progress: bool,
    multiprogress: Arc<Option<MultiProgress>>,
    threshold: f32,
}

impl Grapher {
    /// Creates a new Grapher instance.
    ///
    /// Where `threshold` is the value which when reached matches are considered significant.
    pub fn new(threshold: f32, display_progress: bool) -> Self {
        let mut multiprogress: Arc<Option<MultiProgress>> = Arc::new(None);
        if display_progress {
            multiprogress = Arc::new(Some(MultiProgress::new()));
        }

        Self {
            display_progress,
            multiprogress,
            threshold,
        }
    }

    /// Compare a malware sample to a clean set of libraries and produce a matching pairs reports.
    ///
    /// The `sample_graph` is the Control Flow Graph (CFG) of the malware sample to compare and
    /// `reference_graphs` is the list of reference Control Flow Graphs (CFG) to compare to.
    pub fn compare<T: Sync + Borrow<Disassembly>>(
        &self,
        sample_graph: T,
        reference_graphs: Vec<T>,
    ) -> CompareReport {
        let sample_graph_ref: &Disassembly = sample_graph.borrow();
        let mut matches_list: Vec<BinaryMatch> = Vec::with_capacity(reference_graphs.len());
        let compute_start: Instant = Instant::now();

        { // Compare each sample graph.
            let matches_list: Arc<Mutex<&mut Vec<BinaryMatch>>> =
                Arc::new(Mutex::new(&mut matches_list));

            reference_graphs.par_iter().for_each(|graph| {
                let matches_list: Arc<Mutex<&mut Vec<BinaryMatch>>> = matches_list.clone();
                let matches: BinaryMatch = self.compare_graph_sets(sample_graph_ref, graph.borrow());

                matches_list
                    .lock()
                    .expect("Unexpected error while aggregating matches")
                    .push(matches);
            });
        }

        let compute_elapsed: Duration = compute_start.elapsed();
        CompareReport::new(&sample_graph_ref.name, matches_list, compute_elapsed)
    }

    /// Generate the Control Flow Graph (CFG) for each sample.
    ///
    /// The `sample_list` is a list of paths to each sample to dissassemble.
    #[allow(clippy::assigning_clones)]
    pub fn generate_graphs(
        &self,
        sample_list: &[(String, PathBuf)],
    ) -> Result<Vec<Disassembly>, Error> {
        let mut samples_graph: Vec<Disassembly> = Vec::with_capacity(sample_list.len());

        // Generate the graph for each sample in separate threads.
        {
            let samples_graph: Arc<Mutex<&mut Vec<Disassembly>>> =
                Arc::new(Mutex::new(&mut samples_graph));

            let mut progress_style: Option<ProgressStyle> = None;
            if self.display_progress {
                progress_style = Some(
                    ProgressStyle::with_template(
                        "{spinner:.green} [{elapsed_precise}] {msg:.yellow}",
                    )
                    .expect("Unable to set spinner template"),
                );
            }

            sample_list.par_iter().try_for_each(|(version, sample_path)| -> Result<(), Error> {
                let samples_graph: Arc<Mutex<&mut Vec<Disassembly>>> =
                    samples_graph.clone();

                let progress_style: Option<ProgressStyle> = progress_style.clone();
                let mut _spinner: Option<ProgressBar> = None;

                if let Some(multiprogress) = self.multiprogress.clone().deref() {
                    if let Some(progress_style) = progress_style {
                        let new_spinner: ProgressBar =
                            multiprogress.add(ProgressBar::new_spinner());
                        new_spinner.set_style(progress_style);
                        new_spinner.enable_steady_tick(Duration::from_millis(100));
                        new_spinner.set_message(format!("Disassembling {version} ..."));
                        _spinner = Some(new_spinner);
                    }
                }

                let mut disassembly: Disassembly = Disassembly::new(sample_path.as_path())?;
                disassembly.name = version.clone();

                samples_graph
                    .lock()
                    .expect("Unexpected error while aggregating disassemblies")
                    .push(disassembly);

                Ok(())
            })?;
        }

        Ok(samples_graph)
    }

    // Compare two sets of instruction and return their normalized similarity.
    fn compare_instructions(lhs_ins: &InstructionStreamer, rhs_ins: &InstructionStreamer) -> f32 {
        // NOTE: We care about duplicates so we can't just hashset the problem away.
        let (x, y) = if lhs_ins.len() > rhs_ins.len() {
            (lhs_ins, rhs_ins)
        } else {
            (rhs_ins, lhs_ins)
        };
        let mut other: Vec<&String> = y.iter().map(|i| &i.bytes).collect();
        let mut intersection = 0;
        let mut union = 0;
        for instr in x.iter() {
            union += 1;
            if let Some(i) = other.iter().position(|x| x == &&instr.bytes) {
                intersection += 1;
                other.swap_remove(i);
            }
        }
        union += other.len();

        if union == 0 {
            return 1.0;
        }

        intersection as f32 / union as f32
    }

    // Compare two basic blocks and return their normalized similarity.
    fn compare_blocks(
        l_blocks: &[BasicBlock],
        l_index: usize,
        r_blocks: &[BasicBlock],
        r_index: usize,
    ) -> f32 {
        let local_sim: f32 = if l_blocks[l_index].hash == r_blocks[r_index].hash {
            1.0
        } else {
            // Compare compare local instruction set.
            Grapher::compare_instructions(
                &InstructionStreamer::new(l_blocks, &[l_index]),
                &InstructionStreamer::new(r_blocks, &[r_index]),
            )
        };

        // Get previous instruction sets.
        let l_prev_ins = InstructionStreamer::new(l_blocks, &l_blocks[l_index].in_refs);
        let r_prev_ins = InstructionStreamer::new(r_blocks, &r_blocks[r_index].in_refs);

        // Get next instruction sets.
        let l_next_ins = InstructionStreamer::new(l_blocks, &l_blocks[l_index].out_refs);
        let r_next_ins = InstructionStreamer::new(r_blocks, &r_blocks[r_index].out_refs);

        // Compare previous and next instruction sets.
        let prev_sim: f32 = Grapher::compare_instructions(&l_prev_ins, &r_prev_ins);
        let next_sim: f32 = Grapher::compare_instructions(&l_next_ins, &r_next_ins);

        // Compute the overall similarity.
        ((local_sim * 2.0) + prev_sim + next_sim) / 4.0
    }

    // Compare two Control Flow Graphs (CFG) and return their normalized similarity.
    fn compare_graphs(source_graph: &ControlFlowGraph, target_graph: &ControlFlowGraph) -> f32 {
        // Graph as most similar if their hashes match.
        if source_graph.hash == target_graph.hash {
            return 1.0;
        }

        let l_blocks: &[BasicBlock] = &source_graph.blocks;
        let r_blocks: &[BasicBlock] = &target_graph.blocks;

        let mut top_sims: Vec<f32> = Vec::with_capacity(l_blocks.len());
        for l_index in 0..l_blocks.len() {
            let mut current_sim: f32 = 0.0;
            for r_index in 0..r_blocks.len() {
                let similarity: f32 = Grapher::compare_blocks(l_blocks, l_index, r_blocks, r_index);
                if similarity > current_sim {
                    current_sim = similarity
                }
            }
            top_sims.push(current_sim);
        }
        top_sims.sort_unstable_by(|x, y| x.total_cmp(y).reverse());

        let sample_size: usize = std::cmp::min(l_blocks.len(), r_blocks.len());
        top_sims[..sample_size].iter().sum::<f32>() / sample_size as f32
    }

    // Compare a Control Flow Graph (CFG) against a set of Control Flow Graphs and return the best match.
    fn compare_against_graphs(
        &self,
        reference_graph: &ControlFlowGraph,
        sample_graphs: &Disassembly,
    ) -> Option<MethodMatch> {
        let mut current_top: Option<MethodMatch> = None;

        for sample_graph in &sample_graphs.graphs {
            let similarity: f32 = Grapher::compare_graphs(reference_graph, sample_graph);
            // Check if the match if significant.
            if similarity < self.threshold {
                continue;
            }

            // If so, handle it.
            let current_match = MethodMatch::new(sample_graph, reference_graph, similarity);
            if similarity >= 1.0 {
                current_top = Some(current_match);
                break;
            }

            match current_top {
                Some(ref top) => {
                    if similarity > top.similarity {
                        current_top = Some(current_match);
                    }
                }
                None => {
                    current_top = Some(current_match);
                }
            }
        }

        current_top
    }

    // Compare two control flow graphs.
    fn compare_graph_sets(
        &self,
        sample_graphs: &Disassembly,
        reference_graphs: &Disassembly,
    ) -> BinaryMatch {
        let mut progress_bar: Arc<Option<ProgressBar>> = Arc::new(None);

        if let Some(multiprogress) = self.multiprogress.clone().deref() {
            let new_progress_bar: ProgressBar = multiprogress.add(
                ProgressBar::new(reference_graphs.graphs.len() as u64)
            );
            new_progress_bar.set_style(ProgressStyle::with_template(
                    "[{elapsed_precise} - {eta}] {msg:.yellow} [{wide_bar:.yellow/red}] {pos}/{len} ({percent} %)"
                ).expect("Unable to set progress bar template").progress_chars("#>-"));
            progress_bar = Arc::new(Some(new_progress_bar));
        }

        let matches: Vec<_> = reference_graphs
            .graphs
            .par_iter()
            .filter_map(|reference_graph| {
                let progress: Arc<Option<ProgressBar>> = progress_bar.clone();
                if let Some(progress_bar) = progress.deref() {
                    progress_bar.set_message(format!("Matching {}", reference_graphs.name));
                }

                let current_match = self.compare_against_graphs(reference_graph, sample_graphs);

                if let Some(progress_bar) = progress.deref() {
                    progress_bar.inc(1);
                    if progress_bar.position() >= progress_bar.length().expect("Progress bar's length not set") {
                        progress_bar.finish_and_clear();
                    }
                }

                current_match
            })
            .collect();

        BinaryMatch::new(&sample_graphs.name, &reference_graphs.name, &matches)
    }
}

#[pymethods]
impl Grapher {
    #[new]
    #[pyo3(signature = (*, threshold, display_progress))]
    fn py_new(
        threshold: f32,
        display_progress: bool,
        py: Python
    ) -> PyResult<Self> {
        let thread_handle: thread::JoinHandle<Self> = thread::spawn(move || {
            Grapher::new(threshold, display_progress)
        });

        loop {
            if py.check_signals().is_err() {
                break Err(
                    PyKeyboardInterrupt::new_err("Rust: received ctrl-c.")
                );
            }
            if thread_handle.is_finished() {
                break Ok(thread_handle.join().unwrap());
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[pyo3(name = "compare")]
    fn py_compare(
        &self,
        sample_graph: PyRef<Disassembly>,
        reference_graphs: Vec<PyRef<Disassembly>>,
        py: Python
    ) -> PyResult<CompareReport> {
        let grapher = self.clone();
        let sample_ref: Disassembly = sample_graph.deref().clone();
        let disassemblies: Vec<Disassembly> = reference_graphs.iter().map(|graph| {
            graph.deref().clone()
        }).collect();

        let thread_handle: thread::JoinHandle<CompareReport> = thread::spawn(move || {
            grapher.compare(&sample_ref, disassemblies.iter().collect())
        });

        loop {
            if py.check_signals().is_err() {
                break Err(
                    PyKeyboardInterrupt::new_err("Rust: received ctrl-c.")
                );
            }
            if thread_handle.is_finished() {
                break Ok(thread_handle.join().unwrap());
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[pyo3(name = "generate_graphs")]
    fn generate_graphs_py(
        &self,
        sample_list: Vec<(String, PathBuf)>,
        py: Python
    ) -> PyResult<Vec<Disassembly>> {
        let grapher = self.clone();

        let thread_handle: thread::JoinHandle<Result<Vec<Disassembly>, Error>> = thread::spawn(move || {
            grapher.generate_graphs(&sample_list)
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
}
