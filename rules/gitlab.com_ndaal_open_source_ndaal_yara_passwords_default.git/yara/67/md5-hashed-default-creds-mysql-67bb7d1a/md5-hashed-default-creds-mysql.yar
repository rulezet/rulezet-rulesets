rule md5_hashed_default_creds_mysql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mysql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="e64c7d89f26bd1972efa854d13d7dd61"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="024802c1acb70ae12510effc1779cfa2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}