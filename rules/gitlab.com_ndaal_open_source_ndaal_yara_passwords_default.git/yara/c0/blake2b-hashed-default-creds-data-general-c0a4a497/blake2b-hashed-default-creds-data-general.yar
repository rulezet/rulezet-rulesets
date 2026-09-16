rule blake2b_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a1="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a2="902034c9874f2c0db9a2911f76f7cab56a4bcc5c472d278213f8449ef14d7c8d6b8f640210d5bdced9af79de2f3e9c3f13ff51aaad616a9e08b2380b25c95539"
    $a3="902034c9874f2c0db9a2911f76f7cab56a4bcc5c472d278213f8449ef14d7c8d6b8f640210d5bdced9af79de2f3e9c3f13ff51aaad616a9e08b2380b25c95539"
    $a4="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a5="902034c9874f2c0db9a2911f76f7cab56a4bcc5c472d278213f8449ef14d7c8d6b8f640210d5bdced9af79de2f3e9c3f13ff51aaad616a9e08b2380b25c95539"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}