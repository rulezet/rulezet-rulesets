rule md5_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="048e8512cbfdbd58938561c4bb1683cd"
    $a1="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a2="5581ac876c638364ab7d2000d1d0e9a0"
    $a3="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a4="55899fef2f0b2eba13eb1316b34b3694"
    $a5="7b7bc2512ee1fedcd76bdc68926d4f7b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}