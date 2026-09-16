rule mysql41_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*89DED2CC215FEBF4D5077792E8CBF7B3A3CE6A53"
    $a1="*89DED2CC215FEBF4D5077792E8CBF7B3A3CE6A53"
    $a2="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a3="*11DB58B0DD02E290377535868405F11E4CBEFF58"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}