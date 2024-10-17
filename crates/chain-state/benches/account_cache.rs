#![allow(missing_docs, unreachable_pub)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use reth_chain_state::cache;
use reth_primitives::{Account, Address, B256, U256};
use std::io::Read;

pub fn run_account_benchmark(c: &mut Criterion) {
    let addrs = setup_account_addr(500000);
    setup_account_cache(&addrs);

    c.bench_function("account - quick cache access", |b| {
        b.iter_batched(
            || random_account_addr(&addrs),
            |addr| {
                black_box(account_access_quick_cache(addr));
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("account - quick cache write", |b| {
        b.iter_batched(
            || random_account_addr(&addrs),
            |addr| {
                black_box(account_write_quick_cache(addr));
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn setup_account_cache(addrs: &Vec<Address>) {
    addrs.iter().for_each(|address: &Address| {
        cache::plain_state::PLAIN_ACCOUNTS.insert(
            *address,
            Account { nonce: 1, balance: U256::from(200), bytecode_hash: Some(B256::random()) },
        );
    });
}

fn setup_account_addr(size: u64) -> Vec<Address> {
    let mut lines: Vec<Address> = Vec::new();
    for _i in 0..size {
        lines.push(Address::random());
    }
    lines
}

fn random_account_addr(addrs: &Vec<Address>) -> Address {
    let max = addrs.len();
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..max);
    return addrs[index]
}

fn account_access_quick_cache(addr: Address) {
    let _ = cache::plain_state::PLAIN_ACCOUNTS.get(&addr);
}

fn account_write_quick_cache(address: Address) {
    let _ = cache::plain_state::PLAIN_ACCOUNTS.replace(
        address,
        Account { nonce: 1, balance: U256::from(200), bytecode_hash: Some(B256::random()) },
        true,
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = run_account_benchmark
}
criterion_main!(benches);
