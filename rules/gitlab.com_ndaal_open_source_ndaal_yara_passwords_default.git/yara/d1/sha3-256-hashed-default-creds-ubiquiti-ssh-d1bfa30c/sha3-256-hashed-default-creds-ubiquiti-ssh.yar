rule sha3_256_hashed_default_creds_ubiquiti_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="f5ac746ad512d7ad9a394bd8ac3d1a26084ac0c8a64528f6b6fb6a47666378ff"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="f5ac746ad512d7ad9a394bd8ac3d1a26084ac0c8a64528f6b6fb6a47666378ff"
    $a5="f5ac746ad512d7ad9a394bd8ac3d1a26084ac0c8a64528f6b6fb6a47666378ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}