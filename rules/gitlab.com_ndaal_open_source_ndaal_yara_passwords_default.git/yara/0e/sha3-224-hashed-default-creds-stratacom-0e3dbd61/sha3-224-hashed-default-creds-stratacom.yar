rule sha3_224_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3cc104ff0fb2fc24dca9fb070b345992f7dc937bce23907a694cdef9"
    $a1="65bf012c41d3550a376d4dbc8ad04708040c88f52150c02bb654aa05"
condition:
    ($a0 and $a1)
}