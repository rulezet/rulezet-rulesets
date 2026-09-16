rule sha256_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c9c0ad3d9c726a92479802586b324421fa60b7fe37789c45a2b9f896f353efa"
    $a1="65e8bf0efff22e38f40cde441f543f3696680119a335df49641a347ab43e74b2"
condition:
    ($a0 and $a1)
}