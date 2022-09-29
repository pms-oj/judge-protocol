use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JudgeState {
    /* State */
    DoCompile,
    CompleteCompile,
    /* Results */
    // AC
    Accepted(f64, f64),
    // CE
    CompileError(String),
    // RE* || NZEC
    RuntimeError(i32), // NZEC by isolate
    DiedOnSignal(i32),
    // FJ (Failed to judge)
    InternalError,
    UnknownError,
    LanguageNotFound,
    // TLE
    TimeLimitExceed,
    // MLE
    MemLimitExceed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JudgeRequestBody {
    pub lang: String,
    pub checker_code: Vec<u8>, // encrypted by standard cipher
    pub main_code: Vec<u8>, // encrypted by standard cipher
    pub test_cases: Vec<Vec<u8>>, // encrypted by standard cipher
}

pub struct JudgeResponseBody {
    pub result: JudgeState,
}