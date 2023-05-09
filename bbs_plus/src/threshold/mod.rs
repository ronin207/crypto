//! Implementation of threshold BBS and BBS+ based on the paper [Threshold BBS+ Signatures for Distributed Anonymous Credential Issuance](https://eprint.iacr.org/2023/602)
//! The threshold signing protocol has 3 phases (not communication rounds)
//!     1. This is the randomness generation phase
//!     2. This is the phase where multiplications happen
//!     3. Here the outputs of phases 1 and 2 and the messages to be signed are used to generate the signature.
//!
//! Note that only 3rd phase requires the messages to be known so the first 2 phases can be treated as pre-computation
//! and can be done proactively. Secondly since the communication time among signers is most likely to be the bottleneck
//! in threshold signing, phase 1 and 2 support batching meaning that to generate `n` signatures only a single execution
//! of phase 1 and 2 needs to done, although with larger inputs. Then `n` executions of phase 3 are done to generate
//! the signature.
//! Also its assumed that parties have done the DKG as well as the base OT and stored their results.
//! Both BBS and BBS+ implementations share the same multiplication phase and the base OT phase but their phase 1 is slightly different.

pub mod base_ot_phase;
pub mod cointoss;
pub mod multiplication_phase;
pub mod randomness_generation_phase;
pub mod threshold_bbs;
pub mod threshold_bbs_plus;
pub mod utils;
pub mod zero_sharing;
