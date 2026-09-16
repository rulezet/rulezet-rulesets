rule nthash_hashed_default_creds_aspect
{
    meta:
        id = "6YlGyOf66lWFOQ8k3DD2xW"
        fingerprint = "d4d42b3d501cf0dc0896b4bd08d7d2d184e30a27b3bd952d3d2ba513668eb5a4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b311ea047e7c1d8d5525b11ed14e0c2"
    $a1="63c16cee3f07283c940cd078d2d145ae"
condition:
    ($a0 and $a1)
}