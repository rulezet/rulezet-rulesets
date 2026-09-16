rule ldap_md5_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}9KQ3mZ1qerjf+QzbcMfBVg=="
    $a1="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a2="{MD5}nHISpI7G7v+Wo7+XPqum4Q=="
    $a3="{MD5}lGkisljUhvqWJU14huJ7Mg=="
    $a4="{MD5}CLVBH4SKJYGkFnKnWchzgA=="
    $a5="{MD5}CLVBH4SKJYGkFnKnWchzgA=="
    $a6="{MD5}oqabor2bVJTTrkgrguhWXw=="
    $a7="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}