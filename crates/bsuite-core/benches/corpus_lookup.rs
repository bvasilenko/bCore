use base64::Engine;
use bsuite_core::{
    CorpusEntry, CorpusFile, CorpusResolver, EvidenceMap, PromptResolver, ProvenanceRecord,
    RoutingKey, corpus::canonical_payload_bytes,
};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ed25519_dalek::{Signer, SigningKey};
use std::time::{Duration, Instant};

fn benchmark_entry(index: usize) -> CorpusEntry {
    let key = RoutingKey::ALL[index % RoutingKey::ALL.len()];

    CorpusEntry {
        routing_key: key,
        directive: format!("directive {index}"),
        provenance: ProvenanceRecord {
            run_id: format!("bench-{index}"),
            iteration: index as u32,
            observation_source: "benchmark".to_string(),
            pre_compliance: 0.2,
            post_compliance: 0.9,
        },
    }
}

fn resolver_with_50_entries() -> CorpusResolver {
    let signing_key = SigningKey::from_bytes(&[99; 32]);
    let mut corpus = CorpusFile {
        schema_version: 1,
        signature: String::new(),
        canonical_key_id: "benchmark-key".to_string(),
        entries: (0..50).map(benchmark_entry).collect(),
    };
    let payload = canonical_payload_bytes(&corpus).expect("benchmark corpus canonicalizes");
    corpus.signature = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(signing_key.sign(&payload).to_bytes())
    );
    let toml = toml::to_string(&corpus).expect("benchmark corpus encodes");

    CorpusResolver::from_toml_signed(&toml, &(&signing_key).into())
        .expect("benchmark corpus signature verifies")
}

fn assert_lookup_p99_bound(resolver: &CorpusResolver) {
    for _ in 0..100 {
        let _ = resolver
            .resolve(RoutingKey::BSpector, EvidenceMap::new(), None)
            .expect("benchmark key exists");
    }

    let mut samples = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let started_at = Instant::now();
        let _ = resolver
            .resolve(RoutingKey::BSpector, EvidenceMap::new(), None)
            .expect("benchmark key exists");
        samples.push(started_at.elapsed());
    }

    samples.sort_unstable();
    let p99 = samples[samples.len() * 99 / 100];
    assert!(
        p99 <= Duration::from_micros(10),
        "corpus lookup p99 {p99:?} exceeded 10 microseconds"
    );
}

fn corpus_lookup(c: &mut Criterion) {
    let resolver = resolver_with_50_entries();
    assert_lookup_p99_bound(&resolver);

    c.bench_function("corpus_lookup_resolve", |b| {
        b.iter(|| {
            resolver
                .resolve(black_box(RoutingKey::BSpector), EvidenceMap::new(), None)
                .expect("benchmark key exists")
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(10));
    targets = corpus_lookup
}
criterion_main!(benches);
