rule sha3_224_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a1="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a2="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a3="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
    $a4="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a5="74828cab36f773a4a1323c52715599241fe70b3a6bfb9877a96d0ff2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}