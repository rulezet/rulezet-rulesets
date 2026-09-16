rule nthash_hashed_default_creds_remedy
{
    meta:
        id = "6nhKdgJaX7xBQscqxBF5te"
        fingerprint = "2d54901f8025e37751f5280708b3f2e74122ca582cc0321cccdfddc0d78484d2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47bcaa29839fa166a62a6e98639da51c"
    $a1="8c79c0e8906674cfec9c9bd7ad13367c"
condition:
    ($a0 and $a1)
}