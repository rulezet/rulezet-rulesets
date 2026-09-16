rule sha3_384_hashed_default_creds_ibm_was_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_was_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c932b911817327b78cc140309ba83cb0e5e360ab93195d1e9c328fa045d2ee9af6a3cad254f7055709ebf338fbdae22"
    $a1="7c932b911817327b78cc140309ba83cb0e5e360ab93195d1e9c328fa045d2ee9af6a3cad254f7055709ebf338fbdae22"
condition:
    ($a0 and $a1)
}