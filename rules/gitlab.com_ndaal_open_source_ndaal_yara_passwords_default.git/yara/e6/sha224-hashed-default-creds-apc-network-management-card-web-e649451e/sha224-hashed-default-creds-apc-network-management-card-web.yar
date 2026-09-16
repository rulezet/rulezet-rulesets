rule sha224_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a1="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a2="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a3="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
    $a4="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a5="c3352c01875335502f888606000fee7f03bdf8331037cec22a1bb55a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}