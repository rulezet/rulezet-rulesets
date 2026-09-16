rule nthash_hashed_default_creds_tumbleweed
{
    meta:
        id = "5vMB5bUZ1JVVGLazBcybZo"
        fingerprint = "6621e2afe6b83c09b927e2d79000350127d4aab486e1780fbc6c1311434608db"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tumbleweed."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="366b8b263da6cbb2e217893a27376bc2"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1)
}