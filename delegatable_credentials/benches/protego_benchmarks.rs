use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use delegatable_credentials::{
    protego::{
        issuance::{Credential, SignatureRequestProtocol},
        keys::{IssuerPublicKey, IssuerSecretKey, UserPublicKey, UserSecretKey},
        show::known_signer::CredentialShowProtocol,
    },
    set_commitment::{PreparedSetCommitmentSRS, SetCommitmentSRS},
};

type Fr = <Bls12_381 as Pairing>::ScalarField;

fn setup_for_benchmarks(
    rng: &mut StdRng,
    num_attributes: usize,
    supports_audit: bool,
    supports_revocation: bool,
) -> (
    SetCommitmentSRS<Bls12_381>,
    IssuerSecretKey<Bls12_381>,
    IssuerPublicKey<Bls12_381>,
    UserSecretKey<Bls12_381>,
    UserPublicKey<Bls12_381>,
    Vec<Fr>,
) {
    // Generate SRS
    let (set_comm_srs, _) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
        StdRng,
        Blake2b512,
    >(
        rng,
        num_attributes.try_into().unwrap(),
        None,
    );

    // Generate issuer keys
    let isk = IssuerSecretKey::new(rng, supports_revocation, supports_audit).unwrap();
    let ipk = IssuerPublicKey::new(&isk, set_comm_srs.get_P2());

    // Generate user keys
    let usk = UserSecretKey::new(rng, supports_revocation);
    let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

    // Generate random attributes
    let attributes = (0..num_attributes).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

    (set_comm_srs, isk, ipk, usk, upk, attributes)
}

fn bench_credential_issuance(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let message_count_range = vec![1, 10, 100, 1000, 10000];
    let mut group = c.benchmark_group("Protego credential issuance");

    for count in message_count_range {
        let config = format!("{} attributes", count);
        let (set_comm_srs, isk, ipk, usk, upk, attributes) = 
            setup_for_benchmarks(&mut rng, count, false, false);

        group.bench_function(BenchmarkId::new("issuance", config), |b| {
            b.iter(|| {
                let mut local_rng = StdRng::from_entropy();
                let challenge = Fr::rand(&mut local_rng);
                
                let protocol = SignatureRequestProtocol::init(
                    &mut local_rng,
                    black_box(&usk),
                    black_box(false),
                    black_box(set_comm_srs.get_P1()),
                );

                let (req, req_opening) = protocol
                    .gen_request(
                        &mut local_rng,
                        black_box(attributes.clone()),
                        black_box(&usk),
                        black_box(&challenge),
                        black_box(&set_comm_srs),
                    )
                    .unwrap();

                let sig = req.clone().sign(
                    &mut local_rng,
                    black_box(&isk),
                    black_box(Some(&upk)),
                    black_box(None),
                    black_box(set_comm_srs.get_P1()),
                    black_box(set_comm_srs.get_P2()),
                ).unwrap();

                Credential::new(
                    black_box(req),
                    black_box(req_opening),
                    black_box(sig),
                    black_box(attributes.clone()),
                    black_box(ipk.clone()),
                    black_box(Some(&upk)),
                    black_box(None),
                    black_box(set_comm_srs.get_P1()),
                    black_box(set_comm_srs.get_P2()),
                ).unwrap()
            });
        });
    }
    group.finish();
}

fn bench_credential_showing(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let message_count_range = vec![2, 4, 8, 15, 20, 30, 40, 60];
    let disclosure_percentages = vec![0.0, 0.3, 0.7, 1.0];
    
    let mut group = c.benchmark_group("Protego credential showing");

    for count in message_count_range {
        let (set_comm_srs, isk, ipk, usk, upk, attributes) = 
            setup_for_benchmarks(&mut rng, count, false, false);
        let prep_set_comm_srs = PreparedSetCommitmentSRS::from(set_comm_srs.clone());

        // Create credential first
        let mut local_rng = StdRng::from_entropy();
        let challenge = Fr::rand(&mut local_rng);
        let protocol = SignatureRequestProtocol::init(
            &mut local_rng, &usk, false, set_comm_srs.get_P1()
        );
        
        let (req, req_opening) = protocol
            .gen_request(
                &mut local_rng,
                attributes.clone(),
                &usk,
                &challenge,
                &set_comm_srs,
            )
            .unwrap();

        let sig = req.clone().sign(
            &mut local_rng,
            &isk,
            Some(&upk),
            None,
            set_comm_srs.get_P1(),
            set_comm_srs.get_P2(),
        ).unwrap();

        let credential = Credential::new(
            req,
            req_opening,
            sig,
            attributes.clone(),
            ipk.clone(),
            Some(&upk),
            None,
            set_comm_srs.get_P1(),
            set_comm_srs.get_P2(),
        ).unwrap();

        for percentage in disclosure_percentages.iter() {
            let disclosed_count = (count as f64 * percentage) as usize;
            let config = format!("{} attributes, {}% disclosed", count, percentage * 100.0);

            group.bench_function(BenchmarkId::new("showing", config.clone()), |b| {
                b.iter(|| {
                    let mut local_rng = StdRng::from_entropy();
                    let show_protocol = CredentialShowProtocol::init(
                        &mut local_rng,
                        black_box(credential.clone()),
                        black_box(attributes[..disclosed_count].to_vec()),
                        black_box(Some(&upk)),
                        black_box(None),
                        black_box(&set_comm_srs),
                    ).unwrap();

                    let mut chal_bytes = vec![];
                    show_protocol.challenge_contribution(
                        None,
                        None,
                        None,
                        set_comm_srs.get_P1(),
                        &[1, 2, 3],
                        &mut chal_bytes,
                    ).unwrap();

                    let challenge = Fr::rand(&mut local_rng);
                    show_protocol.gen_show(None, &challenge).unwrap()
                });
            });

            group.bench_function(BenchmarkId::new("verification", config), |b| {
                b.iter(|| {
                    let mut local_rng = StdRng::from_entropy();
                    let show_protocol = CredentialShowProtocol::init(
                        &mut local_rng,
                        credential.clone(),
                        attributes[..disclosed_count].to_vec(),
                        Some(&upk),
                        None,
                        &set_comm_srs,
                    ).unwrap();

                    let challenge = Fr::rand(&mut local_rng);
                    let show = show_protocol.gen_show(None, &challenge).unwrap();
                    
                    show.verify(
                        black_box(&challenge),
                        black_box(attributes[..disclosed_count].to_vec()),
                        black_box(ipk.clone()),
                        black_box(None),
                        black_box(prep_set_comm_srs.clone()),
                    )
                });
            });
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_credential_issuance,
    bench_credential_showing
);
criterion_main!(benches);
