rule sha384_hashed_default_creds_ldap_account_managerlam
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ldap_account_managerlam."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0511dcaaace99058e8117a400a08d0efb0c63b2e97f2c82e5682fd078b1ee082e08a5172564ca4155b9d13fef75ecafb"
    $a1="0511dcaaace99058e8117a400a08d0efb0c63b2e97f2c82e5682fd078b1ee082e08a5172564ca4155b9d13fef75ecafb"
condition:
    ($a0 and $a1)
}