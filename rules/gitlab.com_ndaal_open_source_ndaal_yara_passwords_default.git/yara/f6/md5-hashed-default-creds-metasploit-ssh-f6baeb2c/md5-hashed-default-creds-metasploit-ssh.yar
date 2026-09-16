rule md5_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ce6dcdf21de6a4bce879847e2346532"
    $a1="6ce6dcdf21de6a4bce879847e2346532"
    $a2="2cf79e8f137b5429d1c5a5351e00c5de"
    $a3="2cf79e8f137b5429d1c5a5351e00c5de"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}