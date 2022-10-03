use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::security::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JudgeState {
    /* State */
    DoCompile,
    CompleteCompile(String),
    /* Results */
    // AC
    Accepted(f64, f64),
    // CE
    CompileError(String),
    // RE* || NZEC
    RuntimeError(i32), // NZEC by isolate
    DiedOnSignal(i32),
    // FJ (Failed to judge)
    InternalError(String),
    UnknownError,
    LanguageNotFound,
    // TLE
    TimeLimitExceed,
    // MLE
    MemLimitExceed,
    // Internal
    LockedSlave,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JudgeRequestBody {
    pub main_lang: Uuid,
    pub checker_lang: Uuid,
    pub checker_code: EncMessage, // encrypted by standard cipher
    pub main_code: EncMessage,    // encrypted by standard cipher
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestCaseUpdateBody {
    pub uuid: Uuid,
    pub stdin: EncMessage,
    pub stdout: EncMessage,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JudgeResponseBody {
    pub result: JudgeState,
}
