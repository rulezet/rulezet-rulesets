rule nthash_hashed_default_creds_siips
{
    meta:
        id = "5oEYimKWv3Ik4rFti9b9Dg"
        fingerprint = "802ba5cdf24a7b26c7a037de975413d24bc7f3393b4a946d17b7e3dfbf1f4288"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for siips."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee2a403e9f552d98bd754d1b57eeb87c"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}