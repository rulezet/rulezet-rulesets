rule blake2b_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="886ea35aac3c6c96a8c6fc59ddc89cd44376cd0441cb4d4d1ae957858695280041298013612dafa508dbff7c29fe62f01ca072d6822b85d40d0200dfa1ad1a16"
    $a1="7c2fd17ca3ef62d2767d42b888c466048b1cd0228ff30e9f7fc76d70d504cf4463f63d2cd2f008c8a08ca3684a99211c41c9a8668f41e4d38b1581debc5a198c"
condition:
    ($a0 and $a1)
}