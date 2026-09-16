rule sha3_224_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d85a99dc2399dfd78468a881e5813701010e7d89c8b6075893bae08a"
    $a1="7da6a646362d266261858a7d7f61e3e59d6bb630dc117d291737dbf1"
condition:
    ($a0 and $a1)
}