use std::fs::File;
use std::io::Write;
use std::path::Path;
use boojum::{
    algebraic_props::round_function::AbsorptionModeOverwrite,
    algebraic_props::sponge::GoldilocksPoseidonSponge,
    config::{
        SetupCSConfig,
        ProvingCSConfig,
    },
    field::goldilocks::GoldilocksField,
    field::goldilocks::GoldilocksExt2,
    gadgets::{
        sha256::sha256,
        tables::{
            create_tri_xor_table,
            TriXor4Table,
            create_maj4_table,
            create_ch4_table,
            Ch4Table,
            Maj4Table,
            create_4bit_chunk_split_table,
            Split4BitChunkTable,
        },
        u8::UInt8,
    },
    worker::Worker,
    cs::{
        gates::{
            ConstantsAllocatorGate,
            NopGate,
            ReductionGate,
            FmaGateInBaseFieldWithoutConstant,
        },
        implementations::{
            prover::ProofConfig,
            transcript::GoldilocksPoisedonTranscript,
        },
        cs_builder::*,
        cs_builder_verifier::CsVerifierBuilder,
        implementations::pow::NoPow,
        cs_builder_reference::*,
        GateConfigurationHolder,
        StaticToolboxHolder,
        traits::{
            gate::GatePlacementStrategy,
            cs::ConstraintSystem
        },
        LookupParameters::UseSpecializedColumnsWithTableIdAsConstant, CSGeometry,
    },
    log
};

type F = GoldilocksField;

fn main() {
    type T = GoldilocksPoseidonSponge<AbsorptionModeOverwrite>;
    type TR = GoldilocksPoisedonTranscript;

    let sample: String = "Welcome to the world of boojum".to_string();
    let payload = sample.into_bytes();

    let worker = Worker::new_with_num_threads(8);

    let quotient_lde_degree = 8; // Setup params are not split yet, so it's should be equal to max(FRI lde degree, quotient degree)
    let fri_lde_degree = 8;
    let cap_size = 16;
    let prover_config = ProofConfig {
        fri_lde_factor: fri_lde_degree,
        pow_bits: 0, // not important in practice for anything. 2^20 Blake2s POW uses 30ms
        ..Default::default()
    };

    // TODO: perform satisfiability check

    let geometry = CSGeometry {
        num_columns_under_copy_permutation: 60,
        num_witness_columns: 0,
        num_constant_columns: 4,
        max_allowed_constraint_degree: 4,
    };
    let max_variables = 1 << 25;
    let max_trace_len = 1 << 19;

    type P = boojum::field::goldilocks::MixedGL;
    let builder_impl = CsReferenceImplementationBuilder::<F, P, SetupCSConfig>::new(
        geometry,
        max_variables,
        max_trace_len,
    );
    let builder = new_builder::<_, F>(builder_impl);

    let builder = configure(builder);
    let mut owned_cs = builder.build(());

    // Add tables to the constraint system.
    let table = create_tri_xor_table();
    owned_cs.add_lookup_table::<TriXor4Table, 4>(table);

    let table = create_ch4_table();
    owned_cs.add_lookup_table::<Ch4Table, 4>(table);

    let table = create_maj4_table();
    owned_cs.add_lookup_table::<Maj4Table, 4>(table);

    let table = create_4bit_chunk_split_table::<F, 1>();
    owned_cs.add_lookup_table::<Split4BitChunkTable<1>, 4>(table);

    let table = create_4bit_chunk_split_table::<F, 2>();
    owned_cs.add_lookup_table::<Split4BitChunkTable<2>, 4>(table);

    let mut circuit_input = vec![];

    let cs = &mut owned_cs;

    for el in payload.iter() {
        let el = UInt8::allocate_checked(cs, *el);
        circuit_input.push(el);
    }

    let _output = sha256(cs, &circuit_input);
    drop(cs);
    let (_, padding_hint) = owned_cs.pad_and_shrink();
    let owned_cs = owned_cs.into_assembly();
    owned_cs.print_gate_stats();

    let (base_setup, setup, vk, setup_tree, vars_hint, wits_hint) =
        owned_cs.get_full_setup::<T>(&worker, quotient_lde_degree, cap_size);

    let builder_impl = CsReferenceImplementationBuilder::<F, P, ProvingCSConfig>::new(
        geometry,
        max_variables,
        max_trace_len,
    );

    let builder = new_builder::<_, F>(builder_impl);
    let builder = configure(builder);
    let mut owned_cs = builder.build(());

    // add tables
    let table = create_tri_xor_table();
    owned_cs.add_lookup_table::<TriXor4Table, 4>(table);

    let table = create_ch4_table();
    owned_cs.add_lookup_table::<Ch4Table, 4>(table);

    let table = create_maj4_table();
    owned_cs.add_lookup_table::<Maj4Table, 4>(table);

    let table = create_4bit_chunk_split_table::<F, 1>();
    owned_cs.add_lookup_table::<Split4BitChunkTable<1>, 4>(table);

    let table = create_4bit_chunk_split_table::<F, 2>();
    owned_cs.add_lookup_table::<Split4BitChunkTable<2>, 4>(table);

    // create setup
    let now = std::time::Instant::now();
    log!("Start synthesis for proving");
    let mut circuit_input = vec![];

    let cs = &mut owned_cs;

    for el in payload.iter() {
        let el = UInt8::allocate_checked(cs, *el);
        circuit_input.push(el);
    }

    let _output = sha256(cs, &circuit_input);
    dbg!(now.elapsed());
    log!("Synthesis for proving is done");
    owned_cs.pad_and_shrink_using_hint(&padding_hint);
    let mut owned_cs = owned_cs.into_assembly();

    log!("Proving");
    let witness_set = owned_cs.take_witness_using_hints(&worker, &vars_hint, &wits_hint);
    log!("Witness is resolved");

    let now = std::time::Instant::now();

    let proof = owned_cs.prove_cpu_basic::<GoldilocksExt2, TR, T, NoPow>(
        &worker,
        witness_set,
        &base_setup,
        &setup,
        &setup_tree,
        &vk,
        prover_config,
        (),
    );

    let serialized_proof = match bincode::serialize(&proof) {
        Ok(sz) => sz,
        Err(err) => {
            panic!("couldn't serialize proof {}", err.to_string())
        }
    };

    // Specify the file name
    let proof_path = Path::new("proof.bin");
    let display = proof_path.display();

    // Open a file in write-only mode, returns `io::Result<File>`
    let mut file = match File::create(&proof_path) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(file) => file,
    };

    // Write the JSON string to the file, returns `io::Result<()>`
    match file.write_all(&serialized_proof) {
        Err(why) => panic!("couldn't write to {}: {}", display, why),
        Ok(_) => println!("successfully wrote to {}", display),
    }

    let serialized_vk = match serde_json::to_string(&vk) {
        Ok(k) => k,
        Err(err) => panic!("couldn't serialize verification key: {}", err.to_string())
    };

    let vk_path = Path::new("vk.json");
    let display = vk_path.display();

    let mut file = match File::create(&vk_path) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(file) => file,
    };

    match file.write_all(serialized_vk.as_bytes()) {
        Err(why) => panic!("couldn't write to {}: {}", display, why),
        Ok(_) => println!("successfully wrote to {}", display),
    };

    log!("Proving is done, taken {:?}", now.elapsed());

    let builder_impl = CsVerifierBuilder::<F, GoldilocksExt2>::new_from_parameters(geometry);
    let builder = new_builder::<_, F>(builder_impl);

    let builder = configure(builder);
    let verifier = builder.build(());

    let is_valid = verifier.verify::<T, TR, NoPow>((), &vk, &proof);
    if is_valid {
        log!("Proof verified, yayy 🎉")
    } else {
        log!("Invalid proof, nayy 👎")
    }
}

fn configure<T: CsBuilderImpl<F, T>, GC: GateConfigurationHolder<F>, TB: StaticToolboxHolder>(
    builder: CsBuilder<T, F, GC, TB>,
) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
    let num_lookups = 8;
    let builder = builder.allow_lookup(
        UseSpecializedColumnsWithTableIdAsConstant {
            width: 4,
            num_repetitions: num_lookups,
            share_table_id: true,
        },
    );
    let builder = ConstantsAllocatorGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = ReductionGate::<F, 4>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder =
        NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

    builder
}
