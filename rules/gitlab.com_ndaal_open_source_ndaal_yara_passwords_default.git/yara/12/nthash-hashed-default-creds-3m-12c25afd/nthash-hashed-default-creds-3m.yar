rule nthash_hashed_default_creds_3m
{
    meta:
        id = "7Zma473braAJiB60auIv53"
        fingerprint = "379fac464c20e7500d1ce28cda3d7504bd6a6bb2cfb5656dcabcdd44cb3dfa9e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3680aecee838ae00a97ce9bb72c256d"
    $a1="a3680aecee838ae00a97ce9bb72c256d"
condition:
    ($a0 and $a1)
}