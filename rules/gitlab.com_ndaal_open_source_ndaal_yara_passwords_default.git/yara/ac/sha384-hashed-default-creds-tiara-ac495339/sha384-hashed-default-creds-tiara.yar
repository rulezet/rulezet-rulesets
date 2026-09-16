rule sha384_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c9f709376bc7e12a85c675db5f0af675ddbac325021de19cc1cf7543ebfc7e4489ce3fcd075a52526f70a9c63b6d639"
    $a1="e8744e7407cae08f9170caf620309cfa1ddb1807cc9f0d497e0b03098ad3a63f6633f9509b0a2ce5203c5218fb438382"
condition:
    ($a0 and $a1)
}