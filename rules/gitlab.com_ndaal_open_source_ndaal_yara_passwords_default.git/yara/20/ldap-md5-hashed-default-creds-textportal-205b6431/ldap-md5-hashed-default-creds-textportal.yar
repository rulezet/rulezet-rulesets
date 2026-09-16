rule ldap_md5_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a1="{MD5}6nm1cUtuB2u0sA3Ch5q91w=="
    $a2="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a3="{MD5}1tkXLaB+bETB+8tXH9Co9g=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}