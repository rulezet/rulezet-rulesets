rule nthash_hashed_default_creds_ssh_ssh
{
    meta:
        id = "7j1ElWEBTDARljWaVlvVkh"
        fingerprint = "dec1131e1bbb538c3d508f47d7efc4e2f0a1e39242571ac745700eec71af9ca9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c701863b5e36df53c27c253becd1f93"
    $a1="7c701863b5e36df53c27c253becd1f93"
    $a2="7bdf5168c785cf4a77d28d25e2e18a48"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="3212c03db38b7fb4ba4f1838b9b84e3c"
    $a5="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}