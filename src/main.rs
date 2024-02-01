// Proving a simple circuit with the following operations:
// y = x + A;
// z = y * B;
// w = if y > z { z } else { y }, Min(y, z)
// where A and B are constants and x is input.
// This code snippet is taken from: https://github.com/matter-labs/zksync-era/blob/main/docs/guides/advanced/deeper_overview.md#deeper-overview

use boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use boojum::algebraic_props::sponge::GoldilocksPoseidonSponge;
use boojum::config::DevCSConfig;
use boojum::cs::cs_builder::{CsBuilder, CsBuilderImpl, new_builder};
use boojum::cs::{CSGeometry, GateConfigurationHolder, StaticToolboxHolder};
use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
use boojum::cs::cs_builder_verifier::CsVerifierBuilder;
use boojum::cs::gates::{FmaGateInBaseFieldWithoutConstant, NopGate, SelectionGate};
use boojum::cs::implementations::pow::NoPow;
use boojum::cs::implementations::prover::ProofConfig;
use boojum::cs::implementations::transcript::GoldilocksPoisedonTranscript;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::cs::traits::gate::GatePlacementStrategy;
use boojum::field::goldilocks::{GoldilocksExt2, GoldilocksField};
use boojum::field::{Field, U64Representable};
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u16::UInt16;
use boojum::log;
use boojum::worker::Worker;

fn main() {
    type P = GoldilocksField;
    type F = GoldilocksField;

    let geometry = CSGeometry {
        num_columns_under_copy_permutation: 8,
        num_witness_columns: 0,
        num_constant_columns: 2,
        max_allowed_constraint_degree: 8,
    };

    let max_variables = 512;
    let max_trace_len = 128;

    // Configures the given builder by providing the gates needed to build the circuit.
    fn configure<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = SelectionGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns
        );
        let builder = NopGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );

        builder
    }

    let builder_impl = CsReferenceImplementationBuilder::<F, P, DevCSConfig>::new(
        geometry,
        max_variables,
        max_trace_len,
    );
    let builder = new_builder::<_, F>(builder_impl);

    let builder = configure(builder);
    let mut cs = builder.build(());

    // Add witnesses to the constraint system with evaluations.
    let one = cs.alloc_single_variable_from_witness(GoldilocksField::from_u64_unchecked(1));
    let zero = cs.alloc_single_variable_from_witness(GoldilocksField::from_u64_unchecked(0));
    let x = cs.alloc_single_variable_from_witness(GoldilocksField::from_u64_unchecked(7));
    let a = cs.alloc_single_variable_from_witness(GoldilocksField::from_u64_unchecked(2));
    let b = cs.alloc_single_variable_from_witness(GoldilocksField::from_u64_unchecked(3));
    let y = FmaGateInBaseFieldWithoutConstant::compute_fma(&mut cs, F::ONE, (x, one), F::ONE, a);
    let z = FmaGateInBaseFieldWithoutConstant::compute_fma(&mut cs, F::ONE, (y, b), F::ONE, zero);

    // TODO(dhruv): Figure how to compute selector flag for SelectionGate.
    let w = SelectionGate::select(&mut cs, y, z, zero);
    let result = unsafe { UInt16::from_variable_unchecked(w) };
    log!("Result of the circuit: {}", result.witness_hook(&cs)().unwrap());

    cs.pad_and_shrink();

    let worker = Worker::new_with_num_threads(1);
    let cs = cs.into_assembly();

    let lde_factor_to_use = 32;
    let proof_config = ProofConfig {
        fri_lde_factor: lde_factor_to_use,
        pow_bits: 0,
        ..Default::default()
    };

    let (proof, vk) = cs.prove_one_shot::<
        GoldilocksExt2,
        GoldilocksPoisedonTranscript,
        GoldilocksPoseidonSponge<AbsorptionModeOverwrite>,
        NoPow,
    >(&worker, proof_config, ());

    let builder_impl = CsVerifierBuilder::<F, GoldilocksExt2>::new_from_parameters(geometry);
    let builder = new_builder::<_, F>(builder_impl);

    let builder = configure(builder);
    let verifier = builder.build(());

    let is_valid = verifier.verify::<
        GoldilocksPoseidonSponge<AbsorptionModeOverwrite>,
        GoldilocksPoisedonTranscript,
        NoPow
    >(
        (),
        &vk,
        &proof,
    );

    if is_valid {
        log!("Proof verified, yayy 🎉");
    } else {
        log!("Invalid proof, nayy 👎");
    }
}
