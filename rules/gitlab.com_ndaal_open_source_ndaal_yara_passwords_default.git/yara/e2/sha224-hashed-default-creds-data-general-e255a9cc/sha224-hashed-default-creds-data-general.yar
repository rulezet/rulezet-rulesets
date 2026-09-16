rule sha224_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a1="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a2="a15a0e248f57af4cf585375f3c24fb3e790d5983f23993cbb97bfb83"
    $a3="a15a0e248f57af4cf585375f3c24fb3e790d5983f23993cbb97bfb83"
    $a4="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a5="a15a0e248f57af4cf585375f3c24fb3e790d5983f23993cbb97bfb83"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}