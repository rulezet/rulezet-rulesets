rule nthash_hashed_default_creds_loglogic
{
    meta:
        id = "1HIWRoS4kXROsGF6g9zdp7"
        fingerprint = "e10c80b51c2606d82458e4411c90f526f7c05de15576600fb5c4bc62e0fa2546"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for loglogic."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="804f3fcc038c32bf0f76092b87301109"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="804f3fcc038c32bf0f76092b87301109"
    $a3="afc44ee7351d61d00698796da06b1ebf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}