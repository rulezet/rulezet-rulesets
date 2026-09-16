rule sha3_256_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f562cbc3f4489b1d3b5d84b97b45ed82e263bfec13b4eedbede6944704df2711"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="a7570e993de49d7e3fb80e62f965991071cdb3b3660032500a5da071166db9ff"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="ad02dd5acc3bf0c2af65d421c9fb4623bd65a9d03d5e6aadca4d64df57fe721e"
    $a5="ad02dd5acc3bf0c2af65d421c9fb4623bd65a9d03d5e6aadca4d64df57fe721e"
    $a6="73e65939b85d51c320db19b9d127680484d860ce45f3e8bfbfb318c4c29c0640"
    $a7="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}