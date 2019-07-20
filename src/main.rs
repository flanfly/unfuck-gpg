use std::env;
use std::fs::File;
use std::collections::HashSet;

use sequoia_openpgp::constants::SignatureType;
use sequoia_openpgp::{KeyID, Packet, PacketPile};
use sequoia_openpgp::packet::{Signature};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize;

fn main() {
    let args = env::args().collect::<Vec<_>>();

    if args.len() <= 1 {
        println!("unfuck-gpg unfucks you GnuPG public keyring.\n{} ~/.gnupg/pubring.gpg", args.get(0).unwrap_or(&"unfuck-gpg".to_string()));
    } else {
        for p in &args[1..] {
            println!("unfucking {}...", p);

            let mut kid = HashSet::<KeyID>::default();

            // 1st pass: collect all key fprs
            let pile = PacketPile::from_file(p).unwrap();
            for pkt in pile.into_children() {
                match pkt {
                    Packet::PublicKey(ref k) => { kid.insert(k.keyid()); }
                    Packet::PublicSubkey(ref k) => { kid.insert(k.keyid()); }
                    _ => {}
                }
            }

            println!("{} known keys", kid.len());
            let mut out = File::create(p.clone() + "-unfucked").unwrap();
            let mut filtered = 0;

            // 2nd pass: remove all signatures from unknown keys
            let pile = PacketPile::from_file(p).unwrap();
            let pile = PacketPile::from(pile.into_children().filter(|pkt| {
                let ret = match pkt {
                    Packet::Signature(Signature::V4(s)) => {
                        s.version() <= 4 && (
                        s.get_issuer().map(|x| kid.contains(&x)).unwrap_or(true) 
                            || s.sigtype() != SignatureType::GenericCertificate)
                    }
                    _ => true
                };

                if !ret { filtered += 1; }
                ret
            }).collect::<Vec<_>>());

            println!("filtered {} packets", filtered);

            // write new keyring
            out.set_len(0).unwrap();
            
            println!("writing new keyring to {}", p.clone() + "-unfucked");
            pile.serialize(&mut out).unwrap();
        }
    }
}
