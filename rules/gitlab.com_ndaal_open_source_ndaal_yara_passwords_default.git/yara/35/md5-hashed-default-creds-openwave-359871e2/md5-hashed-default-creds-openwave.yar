rule md5_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c9726ad3881a0d88125e1d0ee15dd76"
    $a1="cfe5d2ebf969d01706383177e6c1e8cb"
    $a2="fa09be8aa44a4075cbf13a8a2319afc9"
    $a3="36bcbb801f5052739af8220c6ea51434"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}