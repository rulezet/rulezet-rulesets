rule nthash_hashed_default_creds_ge_security_inc
{
    meta:
        id = "5T2qmzj9lDvxUJuz2ilN1Z"
        fingerprint = "7467267b29516b29fa1b8f8c28ac4b9fbf97936cd70d8f2cca08f31b1c0fdac5"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge_security_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5fc8b7cb519f6a41bd61c5293ef8df7"
    $a1="e5fc8b7cb519f6a41bd61c5293ef8df7"
condition:
    ($a0 and $a1)
}