use actix::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::security::*;

#[derive(Clone, Debug, Serialize, Deserialize, Message)]
#[rtype(result = "()")]
pub enum JudgeState {
    /* State */
    DoCompile,
    CompleteCompile(String),
    /* Results */
    // AC or Complete
    Accepted(Uuid, u64, u64),
    Complete(Uuid, f64, u64, u64),
    // CE
    CompileError(String),
    // RE* || NZEC
    RuntimeError(Uuid, i32), // NZEC by isolate
    DiedOnSignal(Uuid, i32),
    // FJ (Failed to judge)
    InternalError(Uuid),
    // General
    GeneralError(String),
    UnknownError,
    LanguageNotFound,
    // TLE
    TimeLimitExceed(Uuid),
    // MLE
    MemLimitExceed(Uuid),
    // WA
    WrongAnswer(Uuid, u64, u64),
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
    pub time_limit: u64,          // per case, in ms
    pub mem_limit: u64,           // per case, in ms
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JudgeRequestBodyv2 {
    pub uuid: Uuid,
    pub main_lang: Uuid,
    pub checker_lang: Uuid,
    pub manager_lang: Uuid,
    pub checker_code: EncMessage, // encrypted by standard cipher
    pub main_code: EncMessage,    // encrypted by standard cipher
    pub manager_code: EncMessage, // encrypted by standard cipher
    pub graders: EncMessage,      // encrypted by standard cipher
    pub main_path: String,
    pub object_path: String,
    pub time_limit: u64, // per case, in ms
    pub mem_limit: u64,  // per case, in ms
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
