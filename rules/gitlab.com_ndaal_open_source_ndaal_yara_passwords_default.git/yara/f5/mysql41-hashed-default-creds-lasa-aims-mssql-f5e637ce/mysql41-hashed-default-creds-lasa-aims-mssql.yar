rule mysql41_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8A7C22DABE57CA223754F7CBCEA247C084E2D5A3"
    $a1="*0B0A27832C339662F96E0238AD92FCBCB992A7EA"
    $a2="*8A7C22DABE57CA223754F7CBCEA247C084E2D5A3"
    $a3="*45D8BF1922E6E3FAAF50412D79DE9153B0547141"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}