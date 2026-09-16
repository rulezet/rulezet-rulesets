rule blake2s_hashed_default_creds_beckhoff_automation_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beckhoff_automation_gmbh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="625851e3876e6e6da405c95ac24687ce4bb2cdd8fbd8459278f6f0ce803e13ee"
    $a1="2fcc2fe2175916f1c5756e44c287f9648374a78d8f3b1bec00af8c892a9c6b30"
    $a2="625851e3876e6e6da405c95ac24687ce4bb2cdd8fbd8459278f6f0ce803e13ee"
    $a3="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}