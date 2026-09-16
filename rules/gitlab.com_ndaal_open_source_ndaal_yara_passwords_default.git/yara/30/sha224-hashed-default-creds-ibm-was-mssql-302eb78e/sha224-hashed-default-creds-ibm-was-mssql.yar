rule sha224_hashed_default_creds_ibm_was_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_was_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="251adab9b068f9de8a561d2f7e388d1f4710696f64b9e4ae83e60951"
    $a1="251adab9b068f9de8a561d2f7e388d1f4710696f64b9e4ae83e60951"
condition:
    ($a0 and $a1)
}