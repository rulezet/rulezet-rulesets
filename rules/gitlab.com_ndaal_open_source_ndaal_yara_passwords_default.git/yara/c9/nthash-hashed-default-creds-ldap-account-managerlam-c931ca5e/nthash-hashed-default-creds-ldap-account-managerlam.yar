rule nthash_hashed_default_creds_ldap_account_managerlam
{
    meta:
        id = "3EHXHXwmlJeFTXBanizae"
        fingerprint = "3422d86012451b1da15ba76a113d63ea64436a1034c3b78a98ce8ec3ca8e546d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ldap_account_managerlam."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="017e644b52caa87664a65234f1b498cf"
    $a1="017e644b52caa87664a65234f1b498cf"
condition:
    ($a0 and $a1)
}