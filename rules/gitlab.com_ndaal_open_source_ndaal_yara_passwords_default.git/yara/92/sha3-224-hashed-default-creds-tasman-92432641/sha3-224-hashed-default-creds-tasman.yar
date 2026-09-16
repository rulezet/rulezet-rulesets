rule sha3_224_hashed_default_creds_tasman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tasman."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f35a090cc2ac04cc3a439b923190373b2adf654afd0ce61f8dcb9cf7"
    $a1="1bc96dc63d3c7e8e3df00d1ab3f3f94cd27c427fed7649fa4867eb78"
condition:
    ($a0 and $a1)
}