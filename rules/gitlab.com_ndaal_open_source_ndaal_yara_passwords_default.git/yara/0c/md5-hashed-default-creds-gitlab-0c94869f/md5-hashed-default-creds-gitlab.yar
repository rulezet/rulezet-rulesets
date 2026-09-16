rule md5_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b88cf62b30ece438c1a194279b59bb2c"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="b88cf62b30ece438c1a194279b59bb2c"
    $a3="f7daa65b2aa96290bb47c4d68d11fe6a"
    $a4="b88cf62b30ece438c1a194279b59bb2c"
    $a5="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}