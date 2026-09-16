rule nthash_hashed_default_creds_avaya_contact_center_web
{
    meta:
        id = "5PMeRren1A2j1bx0c6R9WG"
        fingerprint = "4088fa53114593c88feb0e60ba0b786654d0e44febdcde15a26343964be76c5e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for avaya_contact_center_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3726db814d2c2a76946e80c5d006408e"
    $a1="3726db814d2c2a76946e80c5d006408e"
condition:
    ($a0 and $a1)
}