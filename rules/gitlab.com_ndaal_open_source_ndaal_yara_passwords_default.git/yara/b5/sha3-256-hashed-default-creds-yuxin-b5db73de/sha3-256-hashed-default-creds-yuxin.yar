rule sha3_256_hashed_default_creds_yuxin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for yuxin."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
    $a1="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a2="d0b0d9881c508323d71c3d78cd28a8867a2b0701a31e6d844793bbd986135d95"
    $a3="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}