rule mysql41_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*17CE4DB46F337A305C612896DA3B78B6388084EA"
    $a1="*17CE4DB46F337A305C612896DA3B78B6388084EA"
    $a2="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a3="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a4="*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29"
    $a5="*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}