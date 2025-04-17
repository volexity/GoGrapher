# ruff: noqa: PYI021

"""Python types hints for native Rust classes."""

# Builtins.
from pathlib import Path

class MethodMatch:
    """Data Model of the similarity between two Control Flow Graphs (CFG)."""

    @property
    def old_name(self) -> str:
        """Name of the sample method."""

    @property
    def resolved_name(self) -> str:
        """Name of the resolved clean method."""

    @property
    def malware_offset(self) -> int:
        """Offset of the malware method that matched."""

    @property
    def clean_offset(self) -> int:
        """Offset of the clean method that matched."""

    @property
    def similarity(self) -> float:
        """Normalized similarity ratio between the two methods."""

class BinaryMatch:
    """Data Model of the similarity between the Control Flow Gaphs (CFG) of two binaries."""

    @property
    def similarity(self) -> float:
        """Normalized similarity ratio between the two binaries."""

    @property
    def source(self) -> str:
        """The name of the source binary during testing."""

    @property
    def dest(self) -> str:
        """The name of the destination binary during testing."""

    @property
    def matches(self) -> list[MethodMatch]:
        """Returns the array of match results between both binaries."""

class ControlFlowGraph:
    """Control Flow Graph (CFG) data model."""

class Disassembly:
    """Data Model of a disassembled binary."""

    @property
    def name(self) -> str:
        """Name of the disassembled binary."""

    @property
    def path(self) -> str:
        """The path to the disassembled binary."""

    @property
    def graphs(self) -> list[ControlFlowGraph]:
        """The list of Control Flow Graph (CFG) of the disassembly."""

    def __init__(self, sample_path: Path) -> None:
        """Generate the set of Control Flow Graphs (CFG) for the specified binary.

        Args:
            sample_path (Path) : Path to the binary to dissassemble.

        Returns:
            Disassembly : List of Control Flow Graphs (CFG) of the specified binary.
        """

    def filter_symbol(self, search_expression: str) -> Disassembly:
        """Returns a new Disassembly composed of the Control Flow Graphs (CFG) whose name match the supplied regex.

        Args:
            search_expression (str) :  Regex expression used to filter the Disassembly.

        Returns:
            Disassembly : New filtered Disassembly instance.
        """

    def get_subset(self, ratio: float) -> Disassembly:
        """Returns a subset of the disassembly corresponding to the supplied ratio.

        Args:
            ratio (float) : Ratio of the disassembly to keep.

        Returns:
            Disassembly : Subset of the original disassembly.
        """

class CompareReport:
    """GoGrapher compare report data model."""

    @property
    def sample_name(self) -> str:
        """The name of the sample this report belongs to."""

    @property
    def matches(self) -> list[BinaryMatch]:
        """Returns the list of matches contained in this report by Go version."""

    # TODO: Compute Time

    def to_json(self) -> str:
        """Returns the JSON representation the the compare report.

        Returns:
            str : JSON representation of the report.
        """

    @staticmethod
    def from_json(json_data: str) -> CompareReport:
        """Parse a CompareReport from its JSON representation.

        Args:
            json_data (&str) : The JSON data to parse.

        Returns:
            CompareReport : The newly parsed instance of CompareReport.
        """

class Grapher:
    """Compute a summary of the similarities between a malware sample and a set of clean libraries."""

    def __init__(self, *, threshold: float, display_progress: bool = False) -> None:
        """Initialize a new GoGrapher instance.

        Args:
            threshold (f32) : Value at which matches are considered significant.
            display_progress (bool): Weather to output progress updates to the console.

        Returns:
            GoGrapher : The newly initialized GoGrapher instance.
        """

    def compare(self, sample_graph: Disassembly, reference_graphs: list[Disassembly]) -> CompareReport:
        """Compare a malware sample to a clean set of libraries and produce a matching pairs reports.

        Args:
            sample_graph (Disassembly) : The Control Flow Graph (CFG) of the malware sample to compare.
            reference_graphs (list[Disassembly]) : The list of reference Control Flow Graphs (CFG) to compare to.

        Returns:
            CompareReport : The function - library matching pairs.
        """

    @staticmethod
    def generate_graphs(sample_list: list[tuple[str, Path]]) -> list[Disassembly]:
        """Generate the Control Flow Graph (CFG) for each sample.

        Args:
            sample_list (list[tuple[str, Path]]) : The paths to each sample to dissassemble.

        Returns:
            list[Disassembly] : Hashmap of each Control Flow Graph (CFG).
        """

class UnsupportedBinaryFormat(Exception):
    """Raised when an unsupported sample is processed."""

    @property
    def message(self) -> str:
        """Returns the error message of the exception."""

    @property
    def sample(self) -> str:
        """Returns the path to the problematic sample."""
