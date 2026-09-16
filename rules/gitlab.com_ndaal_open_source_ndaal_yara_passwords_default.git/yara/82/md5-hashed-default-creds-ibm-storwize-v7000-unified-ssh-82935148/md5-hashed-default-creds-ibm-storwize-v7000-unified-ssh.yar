rule md5_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ccf6d34d44b09aa8ee7948eee20aa8bf"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="d41e98d1eafa6d6011d3a70f1a5b92f0"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="bed128365216c019988915ed3add75fb"
    $a5="0baea2f0ae20150db78f58cddac442a9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}