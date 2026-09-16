rule sha224_hashed_default_creds_everfocus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for everfocus."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a3="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a4="64cd35385184bab91d1f394b3f64e935fd4bc939333c486a70d9a946"
    $a5="64cd35385184bab91d1f394b3f64e935fd4bc939333c486a70d9a946"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}