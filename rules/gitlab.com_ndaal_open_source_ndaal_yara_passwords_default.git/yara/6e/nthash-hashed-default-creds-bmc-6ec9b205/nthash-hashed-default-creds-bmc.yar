rule nthash_hashed_default_creds_bmc
{
    meta:
        id = "4cWX5p10lPWdY6CFAK1Cqz"
        fingerprint = "d9d0ccf8153e52e44e4b5aee5e899858ce6f221460d8a560411f9454cdaa85d6"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b9a9b4c6f95fb88bb8760e7f53bea6ea"
    $a1="b9a9b4c6f95fb88bb8760e7f53bea6ea"
condition:
    ($a0 and $a1)
}