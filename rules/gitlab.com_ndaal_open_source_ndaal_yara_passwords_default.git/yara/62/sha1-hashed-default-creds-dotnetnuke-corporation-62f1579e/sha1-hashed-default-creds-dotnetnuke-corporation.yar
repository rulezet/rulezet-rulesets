rule sha1_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98ccf140be68f65068348e0a16b162e88f3338c3"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="a8853b73a6af93946b77f9e9cd340e3e90581a61"
    $a3="86dd1cf45142e904cb2e99c2721fac3ca198c6ca"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}