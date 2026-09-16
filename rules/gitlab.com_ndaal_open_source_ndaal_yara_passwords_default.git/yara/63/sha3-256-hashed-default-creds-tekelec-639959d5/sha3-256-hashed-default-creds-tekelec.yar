rule sha3_256_hashed_default_creds_tekelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tekelec."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15b00f8137831443b85524fbd38723468fe52ca1015feb5ff0f9d56a78548544"
    $a1="15b00f8137831443b85524fbd38723468fe52ca1015feb5ff0f9d56a78548544"
condition:
    ($a0 and $a1)
}