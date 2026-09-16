rule blake2b_hashed_default_creds_prtg
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for prtg."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f93a4c85c3999beda5e4b05abf0970252ad29921867adb306099a30ded03e923b98a1701271488ddcfced6ac809d77f173f1003734de5fd06276f58b5dfb31c"
    $a1="7f93a4c85c3999beda5e4b05abf0970252ad29921867adb306099a30ded03e923b98a1701271488ddcfced6ac809d77f173f1003734de5fd06276f58b5dfb31c"
condition:
    ($a0 and $a1)
}