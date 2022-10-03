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
    Accepted(Uuid, f64, f64),
    // CE
    CompileError(String),
    // RE* || NZEC
    RuntimeError(Uuid, i32), // NZEC by isolate
    DiedOnSignal(Uuid, i32),
    // FJ (Failed to judge)
    InternalError(String),
    UnknownError,
    LanguageNotFound,
    // TLE
    TimeLimitExceed(Uuid),
    // MLE
    MemLimitExceed(Uuid),
    // WA
    WrongAnswer(Uuid, f64, f64),
    // Internal
    LockedSlave,
    UnlockedSlave,
    JudgeNotFound,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JudgeRequestBody {
    pub uuid: Uuid,
    pub main_lang: Uuid,
    pub checker_lang: Uuid,
    pub checker_code: EncMessage, // encrypted by standard cipher
    pub main_code: EncMessage,    // encrypted by standard cipher
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestCaseUpdateBody {
    pub uuid: Uuid,
    pub test_uuid: Uuid,
    pub stdin: EncMessage,
    pub stdout: EncMessage,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JudgeResponseBody {
    pub uuid: Uuid,
    pub result: JudgeState,
}
