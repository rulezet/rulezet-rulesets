rule nthash_hashed_default_creds_telco_systems
{
    meta:
        id = "1j0Hn7CzqGNAnMdnZ4xiJw"
        fingerprint = "acd258345a4a499999554915fba62290052d3044b574a41c913febb629f3bb7e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telco_systems."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bb35521f488eea2c2d20599552b9d2f6"
    $a1="bb35521f488eea2c2d20599552b9d2f6"
condition:
    ($a0 and $a1)
}