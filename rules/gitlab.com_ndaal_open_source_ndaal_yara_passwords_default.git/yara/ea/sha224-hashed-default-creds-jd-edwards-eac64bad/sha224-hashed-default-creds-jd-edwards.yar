rule sha224_hashed_default_creds_jd_edwards
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jd_edwards."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="44ccebae9da9f551d1222ece8b18d50e70ea4ab42472229307577368"
    $a1="44ccebae9da9f551d1222ece8b18d50e70ea4ab42472229307577368"
condition:
    ($a0 and $a1)
}