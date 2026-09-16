rule sha3_256_hashed_default_creds_loglogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for loglogic."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f34274e6958a224b0d93d89907ef357a8c17a9e2bd45bb52ca630e4db611ed8"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="8f34274e6958a224b0d93d89907ef357a8c17a9e2bd45bb52ca630e4db611ed8"
    $a3="e5ead65714a14368b08263779941b023f2d991e97fc7e888752616f5da2fded6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}