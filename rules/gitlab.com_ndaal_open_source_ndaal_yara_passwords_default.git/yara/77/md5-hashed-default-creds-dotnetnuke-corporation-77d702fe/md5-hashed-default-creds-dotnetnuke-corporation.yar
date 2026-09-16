rule md5_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59dcf537d3bcf1a8d5371d976acb1caf"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="918b9b18a0534279f5513dc90e884b03"
    $a3="67b3dba8bc6778101892eb77249db32e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}