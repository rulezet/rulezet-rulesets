rule nthash_hashed_default_creds_wang
{
    meta:
        id = "3vVgjsq0qMdVPEUWvkEeMQ"
        fingerprint = "db14e4320d39239981c2d4442e80dab971fab437ad1c8cbd3fc13f319a330532"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wang."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="236a85a6b2737671ced2a296fcf77eb1"
    $a1="75e9dacdfc0067f14b76077f8a27e15c"
condition:
    ($a0 and $a1)
}