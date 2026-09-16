rule ldap_md5_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}cXePWLIKoqXIljMVvS7mKg=="
    $a1="{MD5}cXePWLIKoqXIljMVvS7mKg=="
    $a2="{MD5}S78bkc9vJMk7DDBPgSeAwA=="
    $a3="{MD5}S78bkc9vJMk7DDBPgSeAwA=="
    $a4="{MD5}0UVHTHCuDWSEjmwtnSEUxQ=="
    $a5="{MD5}CqR5MqIbD0cORUc3qiTgow=="
    $a6="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a7="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}