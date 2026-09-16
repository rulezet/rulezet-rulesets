rule nthash_hashed_default_creds_webmail
{
    meta:
        id = "7J9Zu1vGjEC7ZvSTL8W11B"
        fingerprint = "f17d6c0e6e962511080e9d0f42259605f4c8ae49be7331dc8702fcd1539d70fd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1b26c7d0ee32e2365626f3f09c647095"
    $a1="8039375c9da8322eeef1c4b1541a58a7"
condition:
    ($a0 and $a1)
}