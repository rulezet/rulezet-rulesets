rule blake2b_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2171bf606e24b72f3b16075240c9e7c4b86d4b5f99270c9ea4e1add1bdf90c1aaae0f335d47acac508e07bf7bde0fec0e10abce3cd1f9086746fe510d6499374"
    $a1="2171bf606e24b72f3b16075240c9e7c4b86d4b5f99270c9ea4e1add1bdf90c1aaae0f335d47acac508e07bf7bde0fec0e10abce3cd1f9086746fe510d6499374"
condition:
    ($a0 and $a1)
}