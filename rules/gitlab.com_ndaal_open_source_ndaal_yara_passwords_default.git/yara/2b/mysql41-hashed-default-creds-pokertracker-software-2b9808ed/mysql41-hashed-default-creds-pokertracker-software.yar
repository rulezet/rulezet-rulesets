rule mysql41_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*9FB2126F7514B6AF42B20E9E4B8E839B72E31396"
    $a1="*E07CFB2BB669A0C316730464FDC00F452EDB381A"
    $a2="*9C8754FDC5D7E9AE55597702670AAD058DC9754B"
    $a3="*E07CFB2BB669A0C316730464FDC00F452EDB381A"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}