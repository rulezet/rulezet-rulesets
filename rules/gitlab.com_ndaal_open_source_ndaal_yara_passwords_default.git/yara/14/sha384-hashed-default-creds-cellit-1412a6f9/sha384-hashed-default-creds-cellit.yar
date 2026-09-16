rule sha384_hashed_default_creds_cellit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cellit."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bba0b34a984916991d58fab8cfedf50bf9e3983a2472dccc56c72f9b73beec31d084f1cbf8544151f8552d3af69fe4d0"
    $a1="bba0b34a984916991d58fab8cfedf50bf9e3983a2472dccc56c72f9b73beec31d084f1cbf8544151f8552d3af69fe4d0"
condition:
    ($a0 and $a1)
}