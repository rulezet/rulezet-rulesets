rule mysql41_hashed_default_creds_general_instruments
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_instruments."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29"
    $a1="*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29"
condition:
    ($a0 and $a1)
}