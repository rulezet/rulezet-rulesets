rule sha224_hashed_default_creds_patton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14695dc5a4b1d81de1e07388414a7a6926b40e953879dd4f40fecb12"
    $a1="14695dc5a4b1d81de1e07388414a7a6926b40e953879dd4f40fecb12"
    $a2="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
    $a3="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}