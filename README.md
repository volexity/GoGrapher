# GoGrapher

GoGrapher is a Control Flow Graph (CFG) similarity tool to identify matching functions between two binaries.

## How to build

To build GoGrapher use cargo's usual build command :
```bash
cargo build --release
```

Alternatively to build GoGrapher as a python library use maturin instead:
```bash
maturin build --release
```

You can then install the generated .whl file.

## Command Line Usage

Once installed, a new utility `gographer` will be available.

```
Usage: gographer [OPTIONS] <SAMPLE_PATH> [REFERENCE_PATH]...

Arguments:
  <SAMPLE_PATH>        Path to the GO sample to analyze
  [REFERENCE_PATH]...  Path to the GO reference samples to compare to

Options:
  -o, --output <OUTPUT_PATH>   Path of the output JSON report
  -t, --threshold <THRESHOLD>  Value at which matches are considered significant [default: 0.0]
  -h, --help                   Print help
```

Here is a typical workflow using GoGrapher :

```bash
gographer path/to/sample.exe path/to/reference.exe -o path/to/report.json
```

Upon execution, GoGrapher will dissassemble each binary, then compute the similarity between the sample and each reference binary.

Depending on the command line options used, the resulting similarity report will be either printed colorized to STDOUT or saved to the designated output file.

## References

Volexity would like to thanks Mr. Hyun-li Lim of the South Korean university of Kyungnam for his [paper](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf) on CFG similarity algorithm which was the basis of GoGrapher's similarity algorithm implementation.
