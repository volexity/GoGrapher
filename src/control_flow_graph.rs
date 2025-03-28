use chibihash::StreamingChibiHasher;
use pyo3::pyclass;
use smda::function::Instruction;

/// Data model of a Control Flow Graph's (CFG) basic block.
#[derive(Clone)]
pub struct BasicBlock {
    pub(crate) offset: u64,
    pub(crate) instructions: Vec<Instruction>,
    pub(crate) in_refs: Vec<usize>,
    pub(crate) out_refs: Vec<usize>,
    pub(crate) hash: u64,
}

impl BasicBlock {
    /// Create a new BasicBlock instance.
    pub fn new(offset: u64, instructions: &[Instruction]) -> Self {
        // Compute the hash of the block
        let mut hasher: StreamingChibiHasher = StreamingChibiHasher::new(0x1337_u64);
        for ins in instructions {
            hasher.update(ins.bytes.as_bytes());
        }
        Self {
            offset,
            instructions: instructions.to_vec(),
            in_refs: Vec::new(),
            out_refs: Vec::new(),
            hash: hasher.finalize(),
        }
    }

    /// Offset of the block relative to the ".text" segment.
    #[inline]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The list of instruction within the basic block.
    #[inline]
    pub fn instructions(&self) -> &Vec<Instruction> {
        &self.instructions
    }

    /// The list of incoming edges.
    #[inline]
    pub fn in_refs(&self) -> &Vec<usize> {
        &self.in_refs
    }

    /// The list of outgoing edges.
    #[inline]
    pub fn out_refs(&self) -> &Vec<usize> {
        &self.out_refs
    }

    /// Non-Cryptographic hash of the block's instructions.
    #[inline]
    pub fn hash(&self) -> u64 {
        self.hash
    }
}

/// Control Flow Graph (CFG) data model.
#[pyclass]
#[derive(Clone)]
pub struct ControlFlowGraph {
    pub(crate) name: String,
    pub(crate) offset: u64,
    pub(crate) blocks: Vec<BasicBlock>,
    pub(crate) hash: u64,
}

impl ControlFlowGraph {
    /// Creates a new `ControlFlowGraph`.
    pub fn new(name: &str, offset: u64, blocks: Vec<BasicBlock>) -> Self {
        let mut hasher = StreamingChibiHasher::new(0x1337_u64);
        for block in &blocks {
            hasher.update(&block.hash.to_ne_bytes());
        }
        ControlFlowGraph {
            blocks,
            hash: hasher.finalize(),
            name: name.to_owned(),
            offset,
        }
    }

    /// Name of the function of the Control Flow Graph (CFG).
    #[inline]
    pub fn name(&self) -> &String {
        &self.name
    }

    /// Offset of the Control Flow Graph relative to the ".text" segment.
    #[inline]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The list of basic blocks withing the Control Flow Graph.
    #[inline]
    pub fn blocks(&self) -> &Vec<BasicBlock> {
        &self.blocks
    }

    /// Non-Cryptographic hash of the graph's blocks.
    #[inline]
    pub fn hash(&self) -> u64 {
        self.hash
    }
}
