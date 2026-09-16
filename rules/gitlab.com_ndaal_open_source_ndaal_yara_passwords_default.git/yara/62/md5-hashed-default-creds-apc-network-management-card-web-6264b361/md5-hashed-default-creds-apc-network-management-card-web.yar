rule md5_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a1="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a2="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a3="913f9c49dcb544e2087cee284f4a00b7"
    $a4="cbdeaeb2cf5b812c628b2325bcc4c560"
    $a5="336ebbb2179beaa7340a4f1620f3af40"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}