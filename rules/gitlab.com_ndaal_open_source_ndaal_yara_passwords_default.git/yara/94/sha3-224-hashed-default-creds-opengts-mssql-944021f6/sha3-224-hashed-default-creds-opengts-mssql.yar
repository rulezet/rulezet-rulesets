rule sha3_224_hashed_default_creds_opengts_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for opengts_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62a1706ae91f1222ecae6d34169de186dc788325bcd55ade97407c29"
    $a1="4fa0e6dbca1713b9a603a442b486695d269d56b18297d15035fbe474"
condition:
    ($a0 and $a1)
}