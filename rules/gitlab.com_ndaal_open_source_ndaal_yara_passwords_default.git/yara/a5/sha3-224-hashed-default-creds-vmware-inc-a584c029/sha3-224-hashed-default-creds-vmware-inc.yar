rule sha3_224_hashed_default_creds_vmware_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for vmware_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a1="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
condition:
    ($a0 and $a1)
}