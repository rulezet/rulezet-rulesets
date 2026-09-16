rule blake2s_hashed_default_creds_websphere_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for websphere_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a1="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
condition:
    ($a0 and $a1)
}