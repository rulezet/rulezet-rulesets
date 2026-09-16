rule sha3_256_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d7190eb194ff9494625514b6d178c87f99c5973e28c398969d2233f2960a573e"
    $a1="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a2="d7190eb194ff9494625514b6d178c87f99c5973e28c398969d2233f2960a573e"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="d26837c039a088681096c042dc5956da9203126296c341e2301f74369b0ce2eb"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a6="8d95023180bfaa5d3eceb67a79f89c2178db5d9ceb12bd1d2470eedbbe6eaaf3"
    $a7="79de1c617efcf3d784ca3b5d1be7fefb1d1287b079fe4527640c36446cd29ea0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}