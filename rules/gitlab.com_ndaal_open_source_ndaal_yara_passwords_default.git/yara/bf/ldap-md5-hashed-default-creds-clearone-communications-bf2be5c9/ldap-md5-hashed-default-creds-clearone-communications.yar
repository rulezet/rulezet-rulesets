rule ldap_md5_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}8Au7d0eSn6+p0a/Qcdunjg=="
    $a1="{MD5}jtQCs/psrKmI/tZkIhEJyw=="
    $a2="{MD5}bEL6d7n0AiXXxfyMv1RlNg=="
    $a3="{MD5}4kf3/1lzOoDSYplfwA+z7A=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}