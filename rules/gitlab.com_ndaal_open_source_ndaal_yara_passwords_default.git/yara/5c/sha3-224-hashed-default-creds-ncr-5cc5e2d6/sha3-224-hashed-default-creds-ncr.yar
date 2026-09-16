rule sha3_224_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e728b376090f379c8f313cb7f4009339d42f3862b5d1080355f88cea"
    $a1="e728b376090f379c8f313cb7f4009339d42f3862b5d1080355f88cea"
condition:
    ($a0 and $a1)
}