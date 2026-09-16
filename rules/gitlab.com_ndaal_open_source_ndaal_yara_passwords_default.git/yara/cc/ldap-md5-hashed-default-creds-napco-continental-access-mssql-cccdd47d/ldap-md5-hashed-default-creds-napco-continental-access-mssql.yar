rule ldap_md5_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}h8Ilzw74WAgsHmOOrgzOZg=="
    $a1="{MD5}h8Ilzw74WAgsHmOOrgzOZg=="
    $a2="{MD5}vIuAn1XEdEY9L7Bfg3klMg=="
    $a3="{MD5}h8Ilzw74WAgsHmOOrgzOZg=="
    $a4="{MD5}yx8eDfNv4jmtKormKKkU8Q=="
    $a5="{MD5}h8Ilzw74WAgsHmOOrgzOZg=="
    $a6="{MD5}h8Ilzw74WAgsHmOOrgzOZg=="
    $a7="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a8="{MD5}vIuAn1XEdEY9L7Bfg3klMg=="
    $a9="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a10="{MD5}yx8eDfNv4jmtKormKKkU8Q=="
    $a11="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}