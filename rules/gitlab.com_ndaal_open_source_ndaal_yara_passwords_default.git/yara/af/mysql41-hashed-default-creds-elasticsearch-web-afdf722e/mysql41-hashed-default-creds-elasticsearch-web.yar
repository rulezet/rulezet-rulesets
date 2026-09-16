rule mysql41_hashed_default_creds_elasticsearch_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for elasticsearch_web."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7ACE763ED393514FE0C162B93996ECD195FFC4F5"
    $a1="*E55E7E3F6EEFDE61CDEA0BC7D965C8C4F95B94F6"
condition:
    ($a0 and $a1)
}