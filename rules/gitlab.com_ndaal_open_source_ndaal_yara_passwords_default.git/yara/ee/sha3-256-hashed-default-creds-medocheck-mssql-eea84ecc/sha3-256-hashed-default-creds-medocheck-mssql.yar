rule sha3_256_hashed_default_creds_medocheck_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for medocheck_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7984550cf0df965abbac7a655b1cb51e0db27e9f5b20ed27f15772a95f7e4b94"
    $a1="454e9beb105fb6c3a6d6b9a83210f7b758abc780bddcd5bb3d37bfd80484ec06"
condition:
    ($a0 and $a1)
}