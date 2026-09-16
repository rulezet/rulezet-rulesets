rule sha256_hashed_default_creds_meridian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for meridian."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa1eadc4c6995667412681c69ce33adfc9302a2965f521c40908549e670e2e4e"
    $a1="9df6b026a8c6c26e3c3acd2370a16e93fffdc0015ff5bd879218788025db0280"
condition:
    ($a0 and $a1)
}