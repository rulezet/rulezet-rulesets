rule sha1_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a1="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a2="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a3="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
    $a4="59b7bc438df4f2c39736f84add54036f2083ef60"
    $a5="9a27718297218c3757c365d357d13f49d0fa3065"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}