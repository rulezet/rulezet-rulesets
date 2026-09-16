rule md5_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d10458f7225f5e1e5622b0e2bcdb8ea4"
    $a1="d10458f7225f5e1e5622b0e2bcdb8ea4"
    $a2="6241997eaced217d9314bb091957db49"
    $a3="172b5048e8d31bb3236fbf1f649dd76b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}