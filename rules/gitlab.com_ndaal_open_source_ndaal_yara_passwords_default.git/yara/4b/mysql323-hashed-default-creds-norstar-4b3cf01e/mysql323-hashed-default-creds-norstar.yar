rule mysql323_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="596a2c7b1b0d3ec6"
    $a1="1d2b9a9f73b84eb0"
    $a2="5b823d8327438565"
    $a3="1ba66fdf1b1c84f3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}