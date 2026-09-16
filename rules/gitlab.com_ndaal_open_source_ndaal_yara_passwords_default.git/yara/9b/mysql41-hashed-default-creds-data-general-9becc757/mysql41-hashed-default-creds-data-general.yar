rule mysql41_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a1="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a2="*5098B689685C189E7AE0EBEFAD9E14C680815F8E"
    $a3="*5098B689685C189E7AE0EBEFAD9E14C680815F8E"
    $a4="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a5="*5098B689685C189E7AE0EBEFAD9E14C680815F8E"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}