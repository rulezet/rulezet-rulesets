rule sha3_256_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c007b61e8b67ec322918df9f14e516479352c936430baf4cc9e9f6ae441e9ff"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="7c007b61e8b67ec322918df9f14e516479352c936430baf4cc9e9f6ae441e9ff"
    $a3="a33d7fc424197e98a797d8ceb3cdfb47941e3f21d290ccaef47fe492130d9292"
    $a4="7c007b61e8b67ec322918df9f14e516479352c936430baf4cc9e9f6ae441e9ff"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}