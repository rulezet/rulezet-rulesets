rule sha224_hashed_default_creds_bk_ultrasound
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bk_ultrasound."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
    $a1="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
condition:
    ($a0 and $a1)
}