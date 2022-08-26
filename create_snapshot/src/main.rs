use std::cmp;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use solana_runtime::hardened_unpack::open_genesis_config;
use log::{error, info};
use clap::Parser;
use solana_ledger::{bank_forks_utils, blockstore_processor};
use solana_ledger::blockstore::Blockstore;
use solana_ledger::blockstore_options::{AccessType, BlockstoreOptions, BlockstoreRecoveryMode, LedgerColumnOptions, ShredStorageType};
use solana_ledger::blockstore_db::BlockstoreError;
use solana_ledger::blockstore_processor::{BlockstoreProcessorError, ProcessOptions};
use solana_program::clock::Slot;
use solana_runtime::accounts_background_service::{AbsRequestHandler, AbsRequestSender, AccountsBackgroundService};
use solana_runtime::accounts_update_notifier_interface::AccountsUpdateNotifier;
use solana_runtime::bank_forks::BankForks;
use solana_runtime::snapshot_config::SnapshotConfig;
use solana_runtime::snapshot_hash::StartingSnapshotHashes;
use solana_runtime::snapshot_utils;
use solana_sdk::genesis_config::GenesisConfig;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The slot to produce snapshot at
    #[clap(long, env)]
    slot: u64,

    /// The path to output snapshot
    #[clap(long, env)]
    output_dir: PathBuf,

    /// The path to solana ledger folder
    #[clap(long, env)]
    ledger_path: PathBuf,

    /// The RPC to submit transactions
    #[clap(long, env)]
    rpc_url: String,
}

const MAX_GENESIS_ARCHIVE_UNPACKED_SIZE: u64 = 1_000_000_000;

fn main() {
    env_logger::init();
    let args: Args = Args::parse();
    info!("Creating snapshot at slot {}", args.slot);

    let snapshot_archive_path = Some(args.output_dir.clone());
    let incremental_snapshot_archive_path = Some(args.output_dir.clone());

    let genesis_config = open_genesis_config(&args.ledger_path, MAX_GENESIS_ARCHIVE_UNPACKED_SIZE);
    let blockstore = open_blockstore(
        &args.ledger_path,
        AccessType::Secondary,
        Option::from(BlockstoreRecoveryMode::AbsoluteConsistency),
        ShredStorageType::RocksLevel,
        false, // force update to open rocksdb
    );
    let snapshot_type_str = "incremental";
    assert!(
        blockstore.meta(args.slot).unwrap().is_some(),
        "snapshot slot doesn't exist"
    );
    info!(
                "Creating {}snapshot of slot {} in {}",
                snapshot_type_str,
                args.slot,
                args.output_dir.display()
            );
        let bf = load_bank_forks(
            &genesis_config,
            &blockstore,
            ProcessOptions {
                halt_at_slot: Some(args.slot),
                poh_verify: false,
                ..ProcessOptions::default()
            },
            snapshot_archive_path,
            incremental_snapshot_archive_path,
        );
    info!("got bank forks? {}", bf.is_ok());
//        match load_bank_forks(
//            arg_matches,
//            &genesis_config,
//            &blockstore,
//            ProcessOptions {
//                new_hard_forks,
//                halt_at_slot: Some(snapshot_slot),
//                poh_verify: false,
//                accounts_db_config,
//                ..ProcessOptions::default()
//            },
//            snapshot_archive_path,
//            incremental_snapshot_archive_path,
//        ) {
//            Ok((bank_forks, starting_snapshot_hashes)) => {
//                let mut bank = bank_forks
//                    .read()
//                    .unwrap()
//                    .get(snapshot_slot)
//                    .unwrap_or_else(|| {
//                        eprintln!("Error: Slot {} is not available", snapshot_slot);
//                        exit(1);
//                    });
//
//                let child_bank_required = rent_burn_percentage.is_ok()
//                    || hashes_per_tick.is_some()
//                    || remove_stake_accounts
//                    || !accounts_to_remove.is_empty()
//                    || !vote_accounts_to_destake.is_empty()
//                    || faucet_pubkey.is_some()
//                    || bootstrap_validator_pubkeys.is_some();
//
//                if child_bank_required {
//                    let mut child_bank =
//                        Bank::new_from_parent(&bank, bank.collector_id(), bank.slot() + 1);
//
//                    if let Ok(rent_burn_percentage) = rent_burn_percentage {
//                        child_bank.set_rent_burn_percentage(rent_burn_percentage);
//                    }
//
//                    if let Some(hashes_per_tick) = hashes_per_tick {
//                        child_bank.set_hashes_per_tick(match hashes_per_tick {
//                            // Note: Unlike `solana-genesis`, "auto" is not supported here.
//                            "sleep" => None,
//                            _ => {
//                                Some(value_t_or_exit!(arg_matches, "hashes_per_tick", u64))
//                            }
//                        });
//                    }
//                    bank = Arc::new(child_bank);
//                }
//
//                if let Some(faucet_pubkey) = faucet_pubkey {
//                    bank.store_account(
//                        &faucet_pubkey,
//                        &AccountSharedData::new(faucet_lamports, 0, &system_program::id()),
//                    );
//                }
//
//                if remove_stake_accounts {
//                    for (address, mut account) in bank
//                        .get_program_accounts(&stake::program::id(), &ScanConfig::default())
//                        .unwrap()
//                        .into_iter()
//                    {
//                        account.set_lamports(0);
//                        bank.store_account(&address, &account);
//                    }
//                }
//
//                for address in accounts_to_remove {
//                    let mut account = bank.get_account(&address).unwrap_or_else(|| {
//                        eprintln!(
//                            "Error: Account does not exist, unable to remove it: {}",
//                            address
//                        );
//                        exit(1);
//                    });
//
//                    account.set_lamports(0);
//                    bank.store_account(&address, &account);
//                }
//
//                if !vote_accounts_to_destake.is_empty() {
//                    for (address, mut account) in bank
//                        .get_program_accounts(&stake::program::id(), &ScanConfig::default())
//                        .unwrap()
//                        .into_iter()
//                    {
//                        if let Ok(StakeState::Stake(meta, stake)) = account.state() {
//                            if vote_accounts_to_destake
//                                .contains(&stake.delegation.voter_pubkey)
//                            {
//                                if verbose_level > 0 {
//                                    warn!(
//                                                "Undelegating stake account {} from {}",
//                                                address, stake.delegation.voter_pubkey,
//                                            );
//                                }
//                                account.set_state(&StakeState::Initialized(meta)).unwrap();
//                                bank.store_account(&address, &account);
//                            }
//                        }
//                    }
//                }
//
//                if let Some(bootstrap_validator_pubkeys) = bootstrap_validator_pubkeys {
//                    assert_eq!(bootstrap_validator_pubkeys.len() % 3, 0);
//
//                    // Ensure there are no duplicated pubkeys in the --bootstrap-validator list
//                    {
//                        let mut v = bootstrap_validator_pubkeys.clone();
//                        v.sort();
//                        v.dedup();
//                        if v.len() != bootstrap_validator_pubkeys.len() {
//                            eprintln!(
//                                "Error: --bootstrap-validator pubkeys cannot be duplicated"
//                            );
//                            exit(1);
//                        }
//                    }
//
//                    // Delete existing vote accounts
//                    for (address, mut account) in bank
//                        .get_program_accounts(
//                            &solana_vote_program::id(),
//                            &ScanConfig::default(),
//                        )
//                        .unwrap()
//                        .into_iter()
//                    {
//                        account.set_lamports(0);
//                        bank.store_account(&address, &account);
//                    }
//
//                    // Add a new identity/vote/stake account for each of the provided bootstrap
//                    // validators
//                    let mut bootstrap_validator_pubkeys_iter =
//                        bootstrap_validator_pubkeys.iter();
//                    loop {
//                        let identity_pubkey = match bootstrap_validator_pubkeys_iter.next()
//                        {
//                            None => break,
//                            Some(identity_pubkey) => identity_pubkey,
//                        };
//                        let vote_pubkey = bootstrap_validator_pubkeys_iter.next().unwrap();
//                        let stake_pubkey = bootstrap_validator_pubkeys_iter.next().unwrap();
//
//                        bank.store_account(
//                            identity_pubkey,
//                            &AccountSharedData::new(
//                                bootstrap_validator_lamports,
//                                0,
//                                &system_program::id(),
//                            ),
//                        );
//
//                        let vote_account = vote_state::create_account_with_authorized(
//                            identity_pubkey,
//                            identity_pubkey,
//                            identity_pubkey,
//                            100,
//                            VoteState::get_rent_exempt_reserve(&rent).max(1),
//                        );
//
//                        bank.store_account(
//                            stake_pubkey,
//                            &stake_state::create_account(
//                                bootstrap_stake_authorized_pubkey
//                                    .as_ref()
//                                    .unwrap_or(identity_pubkey),
//                                vote_pubkey,
//                                &vote_account,
//                                &rent,
//                                bootstrap_validator_stake_lamports,
//                            ),
//                        );
//                        bank.store_account(vote_pubkey, &vote_account);
//                    }
//
//                    // Warp ahead at least two epochs to ensure that the leader schedule will be
//                    // updated to reflect the new bootstrap validator(s)
//                    let minimum_warp_slot =
//                        genesis_config.epoch_schedule.get_first_slot_in_epoch(
//                            genesis_config.epoch_schedule.get_epoch(snapshot_slot) + 2,
//                        );
//
//                    if let Some(warp_slot) = warp_slot {
//                        if warp_slot < minimum_warp_slot {
//                            eprintln!(
//                                "Error: --warp-slot too close.  Must be >= {}",
//                                minimum_warp_slot
//                            );
//                            exit(1);
//                        }
//                    } else {
//                        warn!("Warping to slot {}", minimum_warp_slot);
//                        warp_slot = Some(minimum_warp_slot);
//                    }
//                }
//
//                if child_bank_required {
//                    while !bank.is_complete() {
//                        bank.register_tick(&Hash::new_unique());
//                    }
//                }
//
//                bank.set_capitalization();
//
//                let bank = if let Some(warp_slot) = warp_slot {
//                    Arc::new(Bank::warp_from_parent(
//                        &bank,
//                        bank.collector_id(),
//                        warp_slot,
//                    ))
//                } else {
//                    bank
//                };
//
//                if is_minimized {
//                    minimize_bank_for_snapshot(
//                        &blockstore,
//                        &bank,
//                        snapshot_slot,
//                        ending_slot.unwrap(),
//                    );
//                }
//
//                println!(
//                    "Creating a version {} {}snapshot of slot {}",
//                    snapshot_version,
//                    snapshot_type_str,
//                    bank.slot(),
//                );
//
//                if is_incremental {
//                    if starting_snapshot_hashes.is_none() {
//                        eprintln!("Unable to create incremental snapshot without a base full snapshot");
//                        exit(1);
//                    }
//                    let full_snapshot_slot = starting_snapshot_hashes.unwrap().full.hash.0;
//                    if bank.slot() <= full_snapshot_slot {
//                        eprintln!(
//                            "Unable to create incremental snapshot: Slot must be greater than full snapshot slot. slot: {}, full snapshot slot: {}",
//                            bank.slot(),
//                            full_snapshot_slot,
//                        );
//                        exit(1);
//                    }
//
//                    let incremental_snapshot_archive_info =
//                        snapshot_utils::bank_to_incremental_snapshot_archive(
//                            ledger_path,
//                            &bank,
//                            full_snapshot_slot,
//                            Some(snapshot_version),
//                            output_directory.clone(),
//                            output_directory,
//                            snapshot_archive_format,
//                            maximum_full_snapshot_archives_to_retain,
//                            maximum_incremental_snapshot_archives_to_retain,
//                        )
//                            .unwrap_or_else(|err| {
//                                eprintln!("Unable to create incremental snapshot: {}", err);
//                                exit(1);
//                            });
//
//                    println!(
//                        "Successfully created incremental snapshot for slot {}, hash {}, base slot: {}: {}",
//                        bank.slot(),
//                        bank.hash(),
//                        full_snapshot_slot,
//                        incremental_snapshot_archive_info.path().display(),
//                    );
//                } else {
//                    let full_snapshot_archive_info =
//                        snapshot_utils::bank_to_full_snapshot_archive(
//                            ledger_path,
//                            &bank,
//                            Some(snapshot_version),
//                            output_directory.clone(),
//                            output_directory,
//                            snapshot_archive_format,
//                            maximum_full_snapshot_archives_to_retain,
//                            maximum_incremental_snapshot_archives_to_retain,
//                        )
//                            .unwrap_or_else(|err| {
//                                eprintln!("Unable to create snapshot: {}", err);
//                                exit(1);
//                            });
//
//                    println!(
//                        "Successfully created snapshot for slot {}, hash {}: {}",
//                        bank.slot(),
//                        bank.hash(),
//                        full_snapshot_archive_info.path().display(),
//                    );
//
//                    if is_minimized {
//                        let starting_epoch = bank.epoch_schedule().get_epoch(snapshot_slot);
//                        let ending_epoch =
//                            bank.epoch_schedule().get_epoch(ending_slot.unwrap());
//                        if starting_epoch != ending_epoch {
//                            warn!("Minimized snapshot range crosses epoch boundary ({} to {}). Bank hashes after {} will not match replays from a full snapshot",
//                                        starting_epoch, ending_epoch, bank.epoch_schedule().get_last_slot_in_epoch(starting_epoch));
//                        }
//                    }
//                }
//
//                println!(
//                    "Shred version: {}",
//                    compute_shred_version(
//                        &genesis_config.hash(),
//                        Some(&bank.hard_forks().read().unwrap())
//                    )
//                );
//            }
//            Err(err) => {
//                eprintln!("Failed to load ledger: {:?}", err);
//                exit(1);
//            }
//        }
}

fn open_blockstore(
    ledger_path: &Path,
    access_type: AccessType,
    wal_recovery_mode: Option<BlockstoreRecoveryMode>,
    shred_storage_type: ShredStorageType,
    force_update_to_open: bool,
) -> Blockstore {
    match Blockstore::open_with_options(
        ledger_path,
        BlockstoreOptions {
            access_type: access_type.clone(),
            recovery_mode: wal_recovery_mode.clone(),
            enforce_ulimit_nofile: true,
            column_options: LedgerColumnOptions {
                shred_storage_type: shred_storage_type.clone(),
                ..LedgerColumnOptions::default()
            },
        },
    ) {
        Ok(blockstore) => blockstore,
        Err(BlockstoreError::RocksDb(err))
        if (err
            .to_string()
            // Missing column family
            .starts_with("Invalid argument: Column family not found:")
            || err
            .to_string()
            // Missing essential file, indicative of blockstore not existing
            .starts_with("IO error: No such file or directory:"))
            && access_type == AccessType::Secondary =>
            {
                error!("Blockstore is incompatible with current software and requires updates");
                if !force_update_to_open {
                    error!("Use --force-update-to-open to allow blockstore to update");
                    exit(1);
                }
                open_blockstore_with_temporary_primary_access(
                    ledger_path,
                    access_type,
                    wal_recovery_mode,
                )
                    .unwrap_or_else(|err| {
                        error!(
                    "Failed to open blockstore (with --force-update-to-open) at {:?}: {:?}",
                    ledger_path, err
                );
                        exit(1);
                    })
            }
        Err(err) => {
            eprintln!("Failed to open blockstore at {:?}: {:?}", ledger_path, err);
            exit(1);
        }
    }
}

/// Open blockstore with temporary primary access to allow necessary,
/// persistent changes to be made to the blockstore (such as creation of new
/// column family(s)). Then, continue opening with `original_access_type`
fn open_blockstore_with_temporary_primary_access(
    ledger_path: &Path,
    original_access_type: AccessType,
    wal_recovery_mode: Option<BlockstoreRecoveryMode>,
) -> Result<Blockstore, BlockstoreError> {
    // Open with Primary will allow any configuration that automatically
    // updates to take effect
    info!("Attempting to temporarily open blockstore with Primary access in order to update");
    {
        let _ = Blockstore::open_with_options(
            ledger_path,
            BlockstoreOptions {
                access_type: AccessType::PrimaryForMaintenance,
                recovery_mode: wal_recovery_mode.clone(),
                enforce_ulimit_nofile: true,
                ..BlockstoreOptions::default()
            },
        )?;
    }
    // Now, attempt to open the blockstore with original AccessType
    info!(
        "Blockstore forced open succeeded, retrying with original access: {:?}",
        original_access_type
    );
    Blockstore::open_with_options(
        ledger_path,
        BlockstoreOptions {
            access_type: original_access_type,
            recovery_mode: wal_recovery_mode,
            enforce_ulimit_nofile: true,
            ..BlockstoreOptions::default()
        },
    )
}

fn load_bank_forks(
    genesis_config: &GenesisConfig,
    blockstore: &Blockstore,
    process_options: ProcessOptions,
    snapshot_archive_path: Option<PathBuf>,
    incremental_snapshot_archive_path: Option<PathBuf>,
) -> Result<(Arc<RwLock<BankForks>>, Option<StartingSnapshotHashes>), BlockstoreProcessorError> {
    let bank_snapshots_dir = blockstore
        .ledger_path()
        .join(if blockstore.is_primary_access() {
            "snapshot"
        } else {
            "snapshot.ledger-tool"
        });

    let mut starting_slot = 0; // default start check with genesis
    let snapshot_config = {
        let full_snapshot_archives_dir =
            snapshot_archive_path.unwrap_or_else(|| blockstore.ledger_path().to_path_buf());
        let incremental_snapshot_archives_dir =
            incremental_snapshot_archive_path.unwrap_or_else(|| full_snapshot_archives_dir.clone());
        if let Some(full_snapshot_slot) =
        snapshot_utils::get_highest_full_snapshot_archive_slot(&full_snapshot_archives_dir)
        {
            let incremental_snapshot_slot =
                snapshot_utils::get_highest_incremental_snapshot_archive_slot(
                    &incremental_snapshot_archives_dir,
                    full_snapshot_slot,
                )
                    .unwrap_or_default();
            starting_slot = std::cmp::max(full_snapshot_slot, incremental_snapshot_slot);
        }

        Some(SnapshotConfig {
            full_snapshot_archive_interval_slots: Slot::MAX,
            incremental_snapshot_archive_interval_slots: Slot::MAX,
            full_snapshot_archives_dir,
            incremental_snapshot_archives_dir,
            bank_snapshots_dir,
            ..SnapshotConfig::default()
        })
    };

    if let Some(halt_slot) = process_options.halt_at_slot {
        // Check if we have the slot data necessary to replay from starting_slot to >= halt_slot.
        //  - This will not catch the case when loading from genesis without a full slot 0.
        if !slot_range_connected(blockstore, starting_slot, halt_slot) {
            eprintln!(
                "Unable to load bank forks at slot {} due to disconnected blocks.",
                halt_slot,
            );
            exit(1);
        }
    }

    let account_paths = if blockstore.is_primary_access() {
        vec![blockstore.ledger_path().join("accounts")]
    } else {
        let non_primary_accounts_path = blockstore.ledger_path().join("accounts.ledger-tool");
        info!(
            "Default accounts path is switched aligning with Blockstore's secondary access: {:?}",
            non_primary_accounts_path
        );

        if non_primary_accounts_path.exists() {
            info!("Clearing {:?}", non_primary_accounts_path);
            if let Err(err) = std::fs::remove_dir_all(&non_primary_accounts_path) {
                eprintln!(
                    "error deleting accounts path {:?}: {}",
                    non_primary_accounts_path, err
                );
                exit(1);
            }
        }

        vec![non_primary_accounts_path]
    };

    let mut accounts_update_notifier = Option::<AccountsUpdateNotifier>::default();

    let (bank_forks, leader_schedule_cache, starting_snapshot_hashes, ..) =
        bank_forks_utils::load_bank_forks(
            genesis_config,
            blockstore,
            account_paths,
            None,
            snapshot_config.as_ref(),
            &process_options,
            None,
            accounts_update_notifier,
        );

    let pruned_banks_receiver =
        AccountsBackgroundService::setup_bank_drop_callback(bank_forks.clone());
    let abs_request_handler = AbsRequestHandler {
        snapshot_request_handler: None,
        pruned_banks_receiver,
    };
    let exit = Arc::new(AtomicBool::new(false));
    let accounts_background_service = AccountsBackgroundService::new(
        bank_forks.clone(),
        &exit,
        abs_request_handler,
        process_options.accounts_db_caching_enabled,
        process_options.accounts_db_test_hash_calculation,
        None,
    );

    let result = blockstore_processor::process_blockstore_from_root(
        blockstore,
        &bank_forks,
        &leader_schedule_cache,
        &process_options,
        None,
        None,
        &AbsRequestSender::default(),
    )
        .map(|_| (bank_forks, starting_snapshot_hashes));

    exit.store(true, Ordering::Relaxed);
    accounts_background_service.join().unwrap();

    result
}

/// Determines if we can iterate from `starting_slot` to >= `ending_slot` by full slots
/// `starting_slot` is excluded from the `is_full()` check
fn slot_range_connected(blockstore: &Blockstore, starting_slot: Slot, ending_slot: Slot) -> bool {
    if starting_slot == ending_slot {
        return true;
    }

    let mut next_slots: VecDeque<_> = match blockstore.meta(starting_slot) {
        Ok(Some(starting_slot_meta)) => starting_slot_meta.next_slots.into(),
        _ => return false,
    };
    while let Some(slot) = next_slots.pop_front() {
        if let Ok(Some(slot_meta)) = blockstore.meta(slot) {
            if slot_meta.is_full() {
                match slot.cmp(&ending_slot) {
                    cmp::Ordering::Less => next_slots.extend(slot_meta.next_slots),
                    _ => return true,
                }
            }
        }
    }

    false
}
