rule ldap_sha1_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}bqUmFCFVaEB1k6Lr+//nYJMj9Tc="
    $a1="{SHA}bqUmFCFVaEB1k6Lr+//nYJMj9Tc="
    $a2="{SHA}PoalQe26xMJpQrJDLQKv3VkIleE="
    $a3="{SHA}PoalQe26xMJpQrJDLQKv3VkIleE="
    $a4="{SHA}wCOqW/jk5XYx3oDdPzdIzm3a+X8="
    $a5="{SHA}wCOqW/jk5XYx3oDdPzdIzm3a+X8="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}