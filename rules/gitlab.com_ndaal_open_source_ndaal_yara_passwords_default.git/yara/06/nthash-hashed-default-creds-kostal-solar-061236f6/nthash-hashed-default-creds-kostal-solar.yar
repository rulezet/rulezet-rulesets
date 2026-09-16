rule nthash_hashed_default_creds_kostal_solar
{
    meta:
        id = "6pdAz3Vmt5J9A7QVEB1oln"
        fingerprint = "c5855591efa2e91f18afd47570b433a24db034d881420a67071362432621c305"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd76fc119d742c1822450137e16ff9fe"
    $a1="4b24e2c374bdffd2937a966ab96a293d"
condition:
    ($a0 and $a1)
}