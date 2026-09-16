rule nthash_hashed_default_creds_shoretel
{
    meta:
        id = "2pVlMLUrIJhYYhCRrtY177"
        fingerprint = "3b5176e68b24cf25a8a7350bfc407d7b0430854858ea6c9650a62e1767753a72"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for shoretel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6597d9fe8469e21d840e2cbff8d43c8b"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="74561893ea1e32f1fab1691c56f6c7a5"
    $a3="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}