rule md5_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a1="0ed3017b911920eae514e12a56ac98d9"
    $a2="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a3="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a4="0e68f753bc601f5d9d04717f95042762"
    $a5="55d598b417478d9e36928935437eafe7"
    $a6="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a7="336ebbb2179beaa7340a4f1620f3af40"
    $a8="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a9="913f9c49dcb544e2087cee284f4a00b7"
    $a10="913f9c49dcb544e2087cee284f4a00b7"
    $a11="913f9c49dcb544e2087cee284f4a00b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}