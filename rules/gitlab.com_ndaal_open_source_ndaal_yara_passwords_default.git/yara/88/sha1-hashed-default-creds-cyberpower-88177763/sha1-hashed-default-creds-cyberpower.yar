rule sha1_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9017347a610d1436c1aaf52764e6578e8fc1a083"
    $a1="9017347a610d1436c1aaf52764e6578e8fc1a083"
    $a2="9017347a610d1436c1aaf52764e6578e8fc1a083"
    $a3="f3a929b3364b471a481f4f7cda0b4559ecde9aba"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}