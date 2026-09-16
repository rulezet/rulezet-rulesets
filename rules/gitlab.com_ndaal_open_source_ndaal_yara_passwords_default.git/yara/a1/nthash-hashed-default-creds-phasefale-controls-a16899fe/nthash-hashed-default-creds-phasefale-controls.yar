rule nthash_hashed_default_creds_phasefale_controls
{
    meta:
        id = "6pKh9aIBa1UrMSHefkEamu"
        fingerprint = "2b869a0359631d942c854277f70e4f0aea02c2c2c57b8ba3293713cb87144e04"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phasefale_controls."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36aa83bdcab3c9fdaf321ca42a31c3fc"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}