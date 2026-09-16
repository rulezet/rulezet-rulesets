rule ldap_sha1_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0v6aFCDCZA7q2DHBDgttiQ7przM="
    $a1="{SHA}tSHKpuHbguWgHJJKQZhwy3K4FjU="
    $a2="{SHA}0v6aFCDCZA7q2DHBDgttiQ7przM="
    $a3="{SHA}QlQ6ScTkFqD7fFp2JtDSJnWcOiI="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}