//! Offline checks of keygen, wallet loading, parties.json parsing and note selection (no node, no proving).

use rd_driver::{
    cmd,
    proto::{select, select_exact},
    wallet::{Me, Parties, load_audit_keys},
};
use serde_json::json;

fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("rd2-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

#[test]
fn keygen_wallet_round_trip_and_parties() {
    let (bi, bank) = (tmp("bi"), tmp("bank"));
    let pb = cmd::keygen(&bi, "bi", true).unwrap();
    let pa = cmd::keygen(&bank, "bank-a", false).unwrap();
    let me = Me::load(&bank, "bank-a").unwrap();
    assert_eq!(hex::encode(me.view_pk), pa["view_pk"].as_str().unwrap());
    assert_eq!(hex::encode(me.address().owner_tag), pa["address"]["owner_tag"].as_str().unwrap());
    assert_eq!(cmd::address(&me)["address"], pa["address"]);
    assert!(pb["bi_audit"][0]["pk"].is_string() && pa.get("bi_audit").is_none());
    let keys = load_audit_keys(&bi).unwrap();
    assert!(keys.contains_key(&1));
    assert!(load_audit_keys(&bank).is_err());

    let parties = Parties(json!({
        "bank-a": {"account_id": pa["account_id"], "view_pk": pa["view_pk"], "address": pa["address"]},
        "bi_audit": [
            {"version": 1, "pk": pb["bi_audit"][0]["pk"], "activation_height": 1, "retire_height": 7},
            {"version": 2, "pk": pb["bi_audit"][0]["pk"], "activation_height": 5, "retire_height": null}],
        "assets": {"rd": "rd#rd"}
    }));
    assert_eq!(parties.audit_key().unwrap().0, 2);
    assert_eq!(parties.address("bank-a").unwrap(), me.address());
    assert_eq!(parties.asset("rd"), "rd#rd");
    assert_eq!(parties.asset("x#y"), "x#y");
    assert!(parties.address("bank-b").is_err());
    let _ = (std::fs::remove_dir_all(bi), std::fs::remove_dir_all(bank));
}

#[test]
fn note_selection() {
    let n = vec![50u128, 300, 120, 100];
    let amt = |x: &u128| *x;
    assert_eq!(select(&n, amt, 100).map(|i| i.iter().map(|k| n[*k]).collect::<Vec<_>>()), Some(vec![100]));
    assert_eq!(select(&n, amt, 301).map(|i| i.iter().map(|k| n[*k]).sum::<u128>()), Some(350));
    assert_eq!(select(&n, amt, 1000), None);
    assert_eq!(select_exact(&n, amt, 150).map(|i| i.iter().map(|k| n[*k]).sum::<u128>()), Some(150));
    assert_eq!(select_exact(&n, amt, 151), None);
}
