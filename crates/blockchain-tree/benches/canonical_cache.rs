#![allow(missing_docs, unreachable_pub)]
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use reth_blockchain_tree::canonical_cache;
#[cfg(feature = "bsc")]
use reth_chainspec::BSC_MAINNET;
use reth_db::{mdbx::DatabaseArguments, open_db_read_only, DatabaseEnv};
use reth_primitives::{alloy_primitives::U160, b256, Address, B256, U256};
use reth_primitives_traits::Account;
use reth_provider::{
    providers::StaticFileProvider, AccountReader, DatabaseProviderRO, ProviderFactory,
};
use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
    str::FromStr,
};

#[cfg(feature = "bsc")]
pub fn run_benchmark(c: &mut Criterion) {
    let provider = setup_db();
    let addrs = setup_addr();
    setup_cache(&addrs);
    let empty: B256 = b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    c.bench_function("db access", |b| {
        b.iter_batched(
            || random_address(&addrs),
            |addr| {
                black_box(access_db(&provider, addr));
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("quick cache access", |b| {
        b.iter_batched(
            || random_address(&addrs),
            |addr| {
                black_box(access_quick_cache(addr));
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("quick cache write", |b| {
        b.iter_batched(
            || random_address(&addrs),
            |addr| {
                black_box(write_quick_cache(addr, empty));
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("db access with warmup1", |b| {
        b.iter_batched(
            || random_address(&addrs),
            |addr| {
                black_box(access_db(&provider, addr));
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("db access with warmup2", |b| {
        b.iter_batched(
            || random_address(&addrs),
            |addr| {
                black_box(access_db(&provider, addr));
            },
            criterion::BatchSize::SmallInput,
        )
    });

    drop(provider);
}

#[cfg(feature = "bsc")]
fn setup_db() -> DatabaseProviderRO<DatabaseEnv> {
    let db_path = std::env::var("RETH_DB_PATH").unwrap();
    let db_path = Path::new(&db_path);
    let static_provider =
        StaticFileProvider::read_write(db_path.join("static_files")).expect("static file provider");
    let db = open_db_read_only(
        db_path.join("db").as_path(),
        DatabaseArguments::default().with_exclusive(Some(false)),
    )
    .unwrap();
    let factory = ProviderFactory::new(db, BSC_MAINNET.clone(), static_provider);
    factory.provider().unwrap()
}

fn setup_cache(addrs: &Vec<Address>) {
    let empty: B256 = b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    // only 10w
    addrs.iter().for_each(|address: &Address| {
        canonical_cache::ACCOUNT_CACHE.insert(
            *address,
            Account { nonce: 1, balance: U256::from(200), bytecode_hash: Some(empty) },
        );
    });

    // another 90w
    for i in 0..900000 {
        canonical_cache::ACCOUNT_CACHE.insert(
            Address::from(U160::from(i)),
            Account { nonce: 1, balance: U256::from(200), bytecode_hash: Some(empty) },
        );
    }
}

fn setup_addr() -> Vec<Address> {
    let path = std::env::var("ADDR_PATH").unwrap();
    let file = File::open(&path).unwrap();

    let reader = io::BufReader::new(file);
    let mut lines: Vec<Address> = Vec::new();

    for line in reader.lines() {
        match line {
            Ok(content) => lines.push(Address::from_str(content.as_str()).unwrap()),
            Err(e) => eprintln!("error: {}", e),
        }
    }
    lines
}

fn random_address(addrs: &Vec<Address>) -> Address {
    let max = addrs.len();
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..max);
    return addrs[index]
}

fn access_db(provider: &DatabaseProviderRO<DatabaseEnv>, addr: Address) {
    let _ = provider.basic_account(addr);
}

fn access_quick_cache(addr: Address) {
    let _ = canonical_cache::ACCOUNT_CACHE.get(&addr);
}

fn write_quick_cache(addr: Address, empty: B256) {
    canonical_cache::ACCOUNT_CACHE
        .insert(addr, Account { nonce: 1, balance: U256::from(100), bytecode_hash: Some(empty) });
}

#[cfg(feature = "bsc")]
criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = run_benchmark
}
#[cfg(feature = "bsc")]
criterion_main!(benches);
