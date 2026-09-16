rule md5_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="8ff32489f92f33416694be8fdc2d4c22"
    $a2="e91e6348157868de9dd8b25c81aebfb9"
    $a3="54b53072540eeeb8f8e9343e71f28176"
    $a4="4a96374e6cedd5ea88c3409a317a304e"
    $a5="54b53072540eeeb8f8e9343e71f28176"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}