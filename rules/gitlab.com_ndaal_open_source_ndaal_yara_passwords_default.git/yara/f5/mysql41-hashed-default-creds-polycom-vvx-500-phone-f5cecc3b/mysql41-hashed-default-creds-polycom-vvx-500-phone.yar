rule mysql41_hashed_default_creds_polycom_vvx_500_phone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom_vvx_500_phone."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*531E182E2F72080AB0740FE2F2D689DBE0146E04"
    $a1="*D89A99106002D77C1D327FC41E005919505638B0"
    $a2="*23AE809DDACAF96AF0FD78ED04B6A265E05AA257"
    $a3="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}