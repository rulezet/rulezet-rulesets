rule nthash_hashed_default_creds_tim_schaab
{
    meta:
        id = "7g4X2Z4jF5KlE6uzjz5guV"
        fingerprint = "b37f8c22fabe9b7c10d6511f86e51d866b4491940e8e9751a150e3947b286f21"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tim_schaab."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="670ae5dfe04c346c3c633f68b898bde9"
    $a1="5170797f5911d35eae8d0a08fe5b0f6d"
condition:
    ($a0 and $a1)
}