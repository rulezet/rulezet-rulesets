rule ldap_md5_hashed_default_creds_gossamer_threads_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gossamer_threads_inc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}Ar2S+qOKqmzA6nXlmTeh7w=="
    $a3="{MD5}Ar2S+qOKqmzA6nXlmTeh7w=="
    $a4="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a5="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}