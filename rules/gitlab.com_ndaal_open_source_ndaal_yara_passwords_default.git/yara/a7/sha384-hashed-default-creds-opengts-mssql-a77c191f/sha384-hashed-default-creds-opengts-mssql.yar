rule sha384_hashed_default_creds_opengts_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for opengts_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="38c073519ffb52e35501d9bc6d365a50b78b5a9b0395c9603fc37d8354b8718e64598ceed5bcfca0ab1546289b2a4bce"
    $a1="1e36ea89d247187ef3b14575b43f69c00b8d57a430153aef9afd15afa50c8ce240d84d0a3f135bae0346b74947f3faf3"
condition:
    ($a0 and $a1)
}