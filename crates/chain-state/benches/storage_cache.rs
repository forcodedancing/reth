#![allow(missing_docs, unreachable_pub)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use reth_chain_state::cache;
use reth_primitives::{Address, B256, U256};
use std::io::Read;

pub fn run_storage_benchmark(c: &mut Criterion) {
    let addrs = setup_storage_addr(1000000);
    setup_storage_cache(&addrs);

    c.bench_function("storage - quick cache access", |b| {
        b.iter_batched(
            || random_storage_addr(&addrs),
            |addr| {
                black_box(storage_access_quick_cache(addr));
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("storage - quick cache write", |b| {
        b.iter_batched(
            || random_storage_addr(&addrs),
            |addr| {
                black_box(storage_write_quick_cache(addr));
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn setup_storage_cache(addrs: &Vec<Address>) {
    addrs.iter().for_each(|address: &Address| {
        cache::plain_state::PLAIN_STORAGES.insert((*address, B256::random()), U256::from(128));
    });
}

fn setup_storage_addr(size: u64) -> Vec<Address> {
    let mut lines: Vec<Address> = Vec::new();
    for _i in 0..size {
        lines.push(Address::random());
    }
    lines
}

fn random_storage_addr(addrs: &Vec<Address>) -> Address {
    let max = addrs.len();
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..max);
    return addrs[index]
}

fn storage_access_quick_cache(addr: Address) {
    let _ = cache::plain_state::PLAIN_STORAGES.get(&(addr, B256::random()));
}

fn storage_write_quick_cache(address: Address) {
    let _ = cache::plain_state::PLAIN_STORAGES.replace(
        (address, B256::random()),
        U256::from(128),
        true,
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = run_storage_benchmark
}
criterion_main!(benches);
