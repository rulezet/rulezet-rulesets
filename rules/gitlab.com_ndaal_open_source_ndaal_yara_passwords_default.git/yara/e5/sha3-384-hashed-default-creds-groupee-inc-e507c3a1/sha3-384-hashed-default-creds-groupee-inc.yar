rule sha3_384_hashed_default_creds_groupee_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for groupee_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a9c66e3498d6087d22d81b9ec38402d0b68ed4abea68105ee276ca59d9eea6c575a0d50976e5949f819041c82895946"
    $a1="e7fb2a9eff4df6b9e48aa3fbab461620eef6d53485fb5de58e85a635e676daa2c3c8b130180ee31b86a9a386145d793b"
condition:
    ($a0 and $a1)
}