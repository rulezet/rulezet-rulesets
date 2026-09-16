rule nthash_hashed_default_creds_bintec
{
    meta:
        id = "1Xj1vqRDrBEPyQxBpVKlTi"
        fingerprint = "72a45c7c94d16fef91e8e5c0a97abed8c8091119d9a2e2896847e22596308647"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e48bcc94ef0e09f090779ff0d78acd0"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="f1e08e22f365da1556331f62fc370997"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="cd764d213992eadbc5bfedd93b9ccc26"
    $a5="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}