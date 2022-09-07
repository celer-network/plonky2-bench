#![allow(incomplete_features)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![feature(generic_const_exprs)]
#![feature(array_windows)]
#![feature(exclusive_range_pattern)]

pub mod config;
pub mod constraint_consumer;
mod get_challenges;
pub mod permutation;
pub mod proof;
pub mod prover;
// pub mod recursive_verifier;
pub mod all_stark;
pub mod cross_table_lookup;
pub mod merkle_stark;
pub mod stark;
pub mod stark_testing;
pub mod util;
pub mod vanishing_poly;
pub mod vars;
pub mod verifier;

pub mod sha256_stark;
pub mod tree_stark;