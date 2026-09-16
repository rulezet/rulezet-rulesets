rule sha3_256_hashed_default_creds_opengts_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for opengts_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3bab7ecbf3cc409b88632c0d2c75f757e83313986f52b3498662a0123e8db3a0"
    $a1="0532c8b41fe70a3ef2db7874da2b0398f4313882498adbb4718674676085bc9d"
condition:
    ($a0 and $a1)
}