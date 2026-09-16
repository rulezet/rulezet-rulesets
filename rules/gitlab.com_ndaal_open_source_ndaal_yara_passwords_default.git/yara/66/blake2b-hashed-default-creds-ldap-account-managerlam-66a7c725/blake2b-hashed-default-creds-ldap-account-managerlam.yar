rule blake2b_hashed_default_creds_ldap_account_managerlam
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ldap_account_managerlam."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="16fd829eb094822e947c000452f7d785ecff3a5b59a5c535a4ee75c1c5c34d4e1666e4c878ce716b9d0218ee46f2181dc774d7f4b82091f5bd93d94c4abcc66b"
    $a1="16fd829eb094822e947c000452f7d785ecff3a5b59a5c535a4ee75c1c5c34d4e1666e4c878ce716b9d0218ee46f2181dc774d7f4b82091f5bd93d94c4abcc66b"
condition:
    ($a0 and $a1)
}