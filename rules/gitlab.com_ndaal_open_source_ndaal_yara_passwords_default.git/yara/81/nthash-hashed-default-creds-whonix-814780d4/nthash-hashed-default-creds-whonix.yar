rule nthash_hashed_default_creds_whonix
{
    meta:
        id = "1sUjMceEPfvzHgfhQCJ7Tu"
        fingerprint = "138b6ab2fdb713a63811304f617ddad4b77d3ea96a86e5f8814c01900ba9195c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for whonix."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6597d9fe8469e21d840e2cbff8d43c8b"
    $a1="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1)
}