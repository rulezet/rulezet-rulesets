rule ldap_md5_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}EMCpaAa6OQngau5UNyHUJA=="
    $a1="{MD5}EMCpaAa6OQngau5UNyHUJA=="
    $a2="{MD5}S0k8AaU0Qy2CC/Il4/bCnQ=="
    $a3="{MD5}d+acE3gSUY41kZa7L16buQ=="
    $a4="{MD5}BuPTb6MM6glVRROYVK0fuQ=="
    $a5="{MD5}BuPTb6MM6glVRROYVK0fuQ=="
    $a6="{MD5}lvmWPiVSCpARyCQBkgeU8A=="
    $a7="{MD5}lvmWPiVSCpARyCQBkgeU8A=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}