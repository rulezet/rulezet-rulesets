rule mysql41_hashed_default_creds_everfocus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for everfocus."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a3="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a4="*40224614CBB87FF21A56337FDF63ED9041147837"
    $a5="*40224614CBB87FF21A56337FDF63ED9041147837"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}