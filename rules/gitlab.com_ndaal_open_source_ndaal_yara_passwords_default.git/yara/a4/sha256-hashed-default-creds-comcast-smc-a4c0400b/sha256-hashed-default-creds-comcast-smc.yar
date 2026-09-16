rule sha256_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4743e040acfb96f4022126d636a3ffd5a41fc9080c21ce0b11e7116a7804470c"
    $a1="d489934ca5788e0ef6804a876ccebc50a28fc28496c801e1c3e91ca3143abf0b"
    $a2="92563d2553584ef62ef475e3600bb4acb6c40ebd3ba5262e764272a05074a7f2"
    $a3="d489934ca5788e0ef6804a876ccebc50a28fc28496c801e1c3e91ca3143abf0b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}