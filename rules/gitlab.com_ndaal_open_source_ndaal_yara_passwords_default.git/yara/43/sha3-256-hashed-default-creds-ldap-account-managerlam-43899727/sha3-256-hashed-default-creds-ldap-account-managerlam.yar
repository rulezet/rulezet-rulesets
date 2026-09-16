rule sha3_256_hashed_default_creds_ldap_account_managerlam
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ldap_account_managerlam."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0283e5dde1443ba70e8623b7de43aff1ee2b4f7a2c48e58690d2ae5c586b57a1"
    $a1="0283e5dde1443ba70e8623b7de43aff1ee2b4f7a2c48e58690d2ae5c586b57a1"
condition:
    ($a0 and $a1)
}