
use log::{Level, LevelFilter};
use merkle_stark::{prover::prove, verifier::verify_stark_proof, config::StarkConfig, stark::Stark, vars::{StarkEvaluationVars, StarkEvaluationTargets}, constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer}, sha256_stark::{Sha2CompressionStark, Sha2StarkCompressor}};
use plonky2::{field::{extension::{Extendable, FieldExtension}, packed::PackedField}, hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder, util::timing::TimingTree};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::hash::hash_types::BytesHash;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type S = Sha2CompressionStark<F, D>;

const NUM_HASHES: usize = 15;

fn main() {
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
	builder.filter_level(LevelFilter::Debug);
    builder.try_init().unwrap();

	let mut compressor = Sha2StarkCompressor::new();
	for _ in 0..NUM_HASHES {
		let left = BytesHash::<32>::rand().0;
		let right = BytesHash::<32>::rand().0;

		compressor.add_instance(left, right);
	}
	
	let trace = compressor.generate();
	
	let config = StarkConfig::standard_fast_config();
	let stark = S::new();
    let mut timing = TimingTree::new("prove", Level::Debug);
	let proof = prove::<F, C, S, D>(
		stark,
		&config,
		trace,
		[],
		&mut timing
	).unwrap();
	timing.print();
	
	verify_stark_proof(stark, proof, &config).unwrap();
}
