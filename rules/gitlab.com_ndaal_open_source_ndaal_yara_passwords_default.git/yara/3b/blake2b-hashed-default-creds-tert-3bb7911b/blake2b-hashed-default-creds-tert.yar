rule blake2b_hashed_default_creds_tert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tert."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11f84c78d500a6c208a0360ed639feca07de49affe51ebe659ade560788f1b312399f55230c90a718f7072985d4e6adb934ec835a431a10a776ebcbc437f59a6"
    $a1="11f84c78d500a6c208a0360ed639feca07de49affe51ebe659ade560788f1b312399f55230c90a718f7072985d4e6adb934ec835a431a10a776ebcbc437f59a6"
condition:
    ($a0 and $a1)
}