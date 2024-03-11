#![feature(generic_const_exprs)]
use std::env;
use std::fmt::Debug;

use log::{debug, Level, LevelFilter};
use merkle_stark::proof::StarkProofWithPublicInputs;
use merkle_stark::recursive_verifier::{
    add_virtual_stark_proof_with_pis, set_stark_proof_with_pis_target, verify_stark_proof_circuit,
};
// use merkle_stark::serialization::Buffer;
use merkle_stark::{
    config::StarkConfig,
    prover::prove,
    serialization::Buffer,
    sha256_stark::{Sha2CompressionStark, Sha2StarkCompressor},
    stark::Stark,
    util::to_u32_array_be,
    verifier::verify_stark_proof,
};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;

const D: usize = 2;

type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type S = Sha2CompressionStark<F, D>;

fn main() {
    let num_hashes = 2;
    println!(
        "\n============== num hashes {} =======================================",
        num_hashes
    );

    let mut compressor = Sha2StarkCompressor::new();
    let zero_bytes = [0; 32];
    for _ in 0..num_hashes {
        let left = to_u32_array_be::<8>(zero_bytes.clone());
        let right = to_u32_array_be::<8>(zero_bytes.clone());
        compressor.add_instance(left, right);
    }

    let mut timing = TimingTree::new("stark", Level::Debug);
    timing.push("prove", Level::Debug);
    timing.push("gen trace", Level::Debug);
    let trace = compressor.generate();
    timing.pop();
    println!("trace len {} width {}", trace[0].len(), trace.len());

    let config = StarkConfig::standard_fast_config();

    debug!("Num Columns: {}", S::COLUMNS);
    let stark = S::new();
    let proof = prove::<F, C, S, D>(stark, &config, trace, [], &mut timing).unwrap();
    let mut buffer = Buffer::new(Vec::new());
    let _ = buffer
        .write_stark_proof_with_public_inputs(&proof)
        .expect("failed to write proof");
    println!("inner proof size {}\n", buffer.bytes().len());
    timing.pop();
    timing.push("verify", Level::Debug);
    verify_stark_proof(stark, proof.clone(), &config).unwrap();
    timing.pop();

    // recursively verify stark in plonky2
    timing.push("verify in plonky2", Level::Debug);
    let outer_proof: ProofWithPublicInputs<F, C, D> = recursive_proof(stark, proof, &config, false).unwrap();
    println!("outer proof size {}", outer_proof.to_bytes().unwrap().len());
    timing.pop();
    timing.print();
}

fn recursive_proof<
    F: RichField + Extendable<D>,
    OuterC: GenericConfig<D, F = F>,
    InnerS: Stark<F, D> + Copy,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    stark: InnerS,
    inner_proof: StarkProofWithPublicInputs<F, InnerC, D>,
    inner_config: &StarkConfig,
    print_gate_counts: bool,
) -> anyhow::Result<ProofWithPublicInputs<F, OuterC, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); InnerS::COLUMNS]:,
    [(); InnerS::PUBLIC_INPUTS]:,
    [(); OuterC::Hasher::HASH_SIZE]:,
{
    let circuit_config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
    let mut pw = PartialWitness::new();
    let degree_bits = inner_proof.proof.recover_degree_bits(inner_config);
    let pt = add_virtual_stark_proof_with_pis(&mut builder, stark, inner_config, degree_bits);
    set_stark_proof_with_pis_target(&mut pw, &pt, &inner_proof);

    verify_stark_proof_circuit::<F, InnerC, InnerS, D>(&mut builder, stark, pt, inner_config);

    if print_gate_counts {
        builder.print_gate_counts(0);
    }

    let data = builder.build::<OuterC>();
    data.prove(pw)
}
