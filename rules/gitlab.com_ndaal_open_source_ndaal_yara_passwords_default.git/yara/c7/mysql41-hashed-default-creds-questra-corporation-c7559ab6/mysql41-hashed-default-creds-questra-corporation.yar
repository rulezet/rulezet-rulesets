rule mysql41_hashed_default_creds_questra_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for questra_corporation."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a1="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a2="*3955BDF8A4BC77DA29BC4580308CAF5711EB068B"
    $a3="*3955BDF8A4BC77DA29BC4580308CAF5711EB068B"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}