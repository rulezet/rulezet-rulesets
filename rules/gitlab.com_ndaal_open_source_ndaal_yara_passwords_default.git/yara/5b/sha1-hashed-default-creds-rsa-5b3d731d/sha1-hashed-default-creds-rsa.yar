rule sha1_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b902e6ff1db9f560443f2048974fd7d386975b0"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="73dd342b9c693012efc970cb8cdd8cf7509d00e7"
    $a3="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a4="f45940808e0868d1dc8f98c5e4a1dad2dc215705"
    $a5="4f26aeafdb2367620a393c973eddbe8f8b846ebd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}