rule blake2s_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a88f86c26a1f2fb9a6bf045e564f68f97bcd613637a819f10f0981183833f739"
    $a1="b5f807b5814ccf4f8d73f88fc13f180a7bd6d9966b36cdab9cb95b8cc2f91c77"
    $a2="b5f807b5814ccf4f8d73f88fc13f180a7bd6d9966b36cdab9cb95b8cc2f91c77"
    $a3="b5f807b5814ccf4f8d73f88fc13f180a7bd6d9966b36cdab9cb95b8cc2f91c77"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}