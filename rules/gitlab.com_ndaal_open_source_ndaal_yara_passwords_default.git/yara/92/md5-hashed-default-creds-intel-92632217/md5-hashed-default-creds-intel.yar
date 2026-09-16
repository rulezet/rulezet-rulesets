rule md5_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a0f848942ce863cf53c0fa6cc684007d"
    $a1="a0f848942ce863cf53c0fa6cc684007d"
    $a2="64438be651abb0d321f728f8ffdb75c5"
    $a3="64438be651abb0d321f728f8ffdb75c5"
    $a4="4e5bbaeafc82ab7aa1385bea8ef5d30a"
    $a5="4e5bbaeafc82ab7aa1385bea8ef5d30a"
    $a6="21232f297a57a5a743894a0e4a801fc3"
    $a7="63a9f0ea7bb98050796b649e85481845"
    $a8="b123bc09e72c15d85ec90e1f1adcbd80"
    $a9="9e95f6d797987b7da0fb293a760fe57e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}