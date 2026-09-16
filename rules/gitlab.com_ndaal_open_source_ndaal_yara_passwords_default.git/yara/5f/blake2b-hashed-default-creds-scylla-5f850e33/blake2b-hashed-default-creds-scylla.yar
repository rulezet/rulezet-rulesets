rule blake2b_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69b1dc5e659bf59b635bdd5f9bf05d6e67039444c0f8c0b9249dc4f6deb31d8413c6b49d169f37b1e12d0a61d1569aaf78a77e64e5718644fb74af25cb79a6c7"
    $a1="69b1dc5e659bf59b635bdd5f9bf05d6e67039444c0f8c0b9249dc4f6deb31d8413c6b49d169f37b1e12d0a61d1569aaf78a77e64e5718644fb74af25cb79a6c7"
condition:
    ($a0 and $a1)
}