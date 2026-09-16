rule mysql41_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4B251511F5DE09F5603EDADE2E468A76C2E240A6"
    $a1="*49AA0B0308454DCE01A23BB7E3EFBE5C77F11B66"
    $a2="*46ADBBFA69A68FFDF36246D68FBC78E3EEA83CB1"
    $a3="*49AA0B0308454DCE01A23BB7E3EFBE5C77F11B66"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}