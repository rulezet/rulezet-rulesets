rule ldap_md5_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}l/q3zqGhD6cMf7H2F53iyw=="
    $a1="{MD5}rUL2aXsDW3WA5P75O+ILTQ=="
    $a2="{MD5}2fkTP7EgzWCWhwvCtJaAWw=="
    $a3="{MD5}2fkTP7EgzWCWhwvCtJaAWw=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}