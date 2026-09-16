rule sha256_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
    $a1="bb96087835b2a082a33b6d7ee3ae240d07f8de033aaab3248dc0ff99705b042c"
condition:
    ($a0 and $a1)
}