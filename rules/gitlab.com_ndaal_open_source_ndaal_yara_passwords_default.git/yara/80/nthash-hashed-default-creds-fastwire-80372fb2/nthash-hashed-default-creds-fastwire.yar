rule nthash_hashed_default_creds_fastwire
{
    meta:
        id = "4sE5NSi1JWFhI2tayQ3nQL"
        fingerprint = "fc8f2930404ea6ed2bed2d33f7be81bfef65026d98083088bf148d1cdeaad1fe"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fastwire."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f841021cc4a7ba4a12a491dbbd930d23"
    $a1="8704e502ee36d1101f1eaf9b706e94b6"
condition:
    ($a0 and $a1)
}