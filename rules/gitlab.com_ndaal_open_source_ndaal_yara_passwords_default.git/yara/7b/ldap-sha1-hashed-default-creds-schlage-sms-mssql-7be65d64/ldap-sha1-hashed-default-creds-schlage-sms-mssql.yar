rule ldap_sha1_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ETMhUVf/ksxhoXxKY4Xn6cGOiQ8="
    $a1="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a2="{SHA}ETMhUVf/ksxhoXxKY4Xn6cGOiQ8="
    $a3="{SHA}S2s2I0OnQq1AdD8+GOl3AjYHZ0Y="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}