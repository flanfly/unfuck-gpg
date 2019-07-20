UNFUCK GnuPG
============

This tool removes all 3rd party signatures for you GnuPG keyring. In case your a victim of the signature spamming attack on the SKS pool, you can use this tool to temporarly get a working keyring.

Usage
-----

First, **backup your existing keyring**. This program was written in two sessions past midnight, it has bugs!

```bash
cp ~/.gnupg/pubring.gpg ~/pubring.gpg
```

Then call build the tool, run it on your keyring and overwrite GnuPG's keyring with the filtered one.

```bash
cp ~/.gnupg/pubring.gpg ./pubring.gpg
cargo run -- ./pubring.gpg
cp ./pubring.gpg-unfucked ~/.gnupg/pubring.gpg
```

Check that everything works again.

```bash
# lists all public keys
gpg -k

# lists you secret keys
gpg -K
```

Happy hacking. Please check out [Sequoia](https://sequoia-pgp.org/)!

