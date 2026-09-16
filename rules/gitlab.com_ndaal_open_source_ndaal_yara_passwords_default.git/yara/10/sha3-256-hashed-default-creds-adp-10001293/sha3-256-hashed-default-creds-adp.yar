rule sha3_256_hashed_default_creds_adp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adp."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8e5d79468855b0aa30152460f869669ebece49a748839c70f19d17bb2a2239e2"
    $a1="78377bddcc5fb7199a28965a65772069ce9de533aa0b7ac7c63fde2e2cc95966"
condition:
    ($a0 and $a1)
}