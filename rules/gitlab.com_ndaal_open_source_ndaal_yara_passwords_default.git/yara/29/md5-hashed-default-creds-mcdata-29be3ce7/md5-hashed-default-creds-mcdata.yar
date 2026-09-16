rule md5_hashed_default_creds_mcdata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcdata."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a2="2d80018c44940facbd448683a185cd9e"
    $a3="eb260502386693867ea264f3a523edf4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}