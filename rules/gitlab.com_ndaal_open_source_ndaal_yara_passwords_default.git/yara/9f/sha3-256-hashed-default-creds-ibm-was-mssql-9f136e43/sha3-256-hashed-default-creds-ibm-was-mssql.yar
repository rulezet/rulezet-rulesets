rule sha3_256_hashed_default_creds_ibm_was_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_was_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="003d8e7819c382f2b5860ec7ce6e464cd39e1e132d082d265316c8dfb2c3fed9"
    $a1="003d8e7819c382f2b5860ec7ce6e464cd39e1e132d082d265316c8dfb2c3fed9"
condition:
    ($a0 and $a1)
}