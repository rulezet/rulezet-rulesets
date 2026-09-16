rule nthash_hashed_default_creds_nexsan
{
    meta:
        id = "UemsTwdvTowihoRnkQMMi"
        fingerprint = "8c6d96ccb4fce980790aa5a4c9e97fd52b2e791b4ce3b04d97e3c792fef9e82e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nexsan."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b592e4f8178b4c75788531b2e747687"
    $a1="11a01c4a0f2f228796c93fa0ca1a634d"
condition:
    ($a0 and $a1)
}