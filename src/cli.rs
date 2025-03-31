use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use colored_json::ToColoredJson;
use pyo3::{pyclass, pymethods};

use crate::compare_report::CompareReport;
use crate::disassembly::Disassembly;
use crate::grapher::Grapher;


#[derive(Parser)]
pub struct Args {
    /// Path to the GO sample to analyze.
    pub sample_path: PathBuf,

    /// Path to the GO reference samples to compare to.
    pub reference_path: Vec<PathBuf>,

    /// Path of the output JSON report.
    #[arg(short = 'o', long = "output")]
    pub output_path: Option<PathBuf>,

    /// Value at which matches are considered significant.
    #[arg(short = 't', long = "threshold", default_value = "0.0")]
    pub threshold: f32,
}

/// Implements the comand line interface of GoGrapher.
#[pyclass]
pub struct Cli;

impl Cli {
    /// Parse the cli arguments and execute the requested commands.
    pub fn run_cli() {
        Cli::parse_cli(&std::env::args().collect::<Vec<String>>());
    }

    fn parse_cli(args: &[String]) {
        // Implements the comand line interface of GoGrapher.
        let args = Args::parse_from(args);
        let grapher: Grapher = Grapher::new(args.threshold, true);

        let mut reference_paths: Vec<(String, PathBuf)> = args.reference_path.iter().map(|path|{
            let filename: String = path.file_name()
                .expect("Reference path missing filename")
                .to_str()
                .expect("Reference filename conversion failed")
                .to_string();
            (filename, path.clone())
        }).collect();

        let sample_filename: String = args.sample_path.file_name()
            .expect("Sample path missing filename")
            .to_str()
            .expect("Couldn't convert filename")
            .to_string();
        reference_paths.push((sample_filename, args.sample_path.clone()));

        // Disassemble the necessary samples.
        let mut samples_graph: Vec<Disassembly> = grapher.generate_graphs(&reference_paths);
        let sample_index: usize = samples_graph
            .iter()
            .position(|disassembly| disassembly.path == args.sample_path)
            .expect("Missing sample disassembly");
        let malware_graph: Disassembly = samples_graph.swap_remove(sample_index);

        let report: CompareReport = grapher.compare(malware_graph, samples_graph);
        let report_json: String = report.to_json();

        if let Some(path) = args.output_path {
            if let Ok(mut out_file) = File::create(path) {
                out_file.write_all(report_json.as_bytes()).expect("Couldn't write report file");
            }
        } else {
            let report_colored: String = report_json.to_colored_json_auto().expect("Couln't colorise report file");
            println!("{report_colored}");
        }
    }
}

#[pymethods]
impl Cli {
    /// Parse the cli arguments and execute the requested commands.
    #[staticmethod]
    #[pyo3(name = "run_cli")]
    fn run_cli_py() {
        Cli::parse_cli(&std::env::args().collect::<Vec<String>>()[1..]);
    }
}
