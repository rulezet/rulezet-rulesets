rule nthash_hashed_default_creds_helmholz_systeme
{
    meta:
        id = "7ON8LU7jbHz6sEynsFKlaW"
        fingerprint = "3ad051627a7a03411497b1d89eacbf3e2d00d44bdafcca0ec25b23c29feff6e3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for helmholz_systeme."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="2a2f55b2f53b7a368ef99512ac96ce9e"
condition:
    ($a0 and $a1)
}