rule sha3_512_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7c9f84a86b7d943758a387a2c3229cbcbb8053994c3539d0161f503ef9bd4c95197bb6adc6582da384eaf2c6e4b7c8fc0deb4eea6da43fc927f3b83818400bd"
    $a1="e7c9f84a86b7d943758a387a2c3229cbcbb8053994c3539d0161f503ef9bd4c95197bb6adc6582da384eaf2c6e4b7c8fc0deb4eea6da43fc927f3b83818400bd"
condition:
    ($a0 and $a1)
}