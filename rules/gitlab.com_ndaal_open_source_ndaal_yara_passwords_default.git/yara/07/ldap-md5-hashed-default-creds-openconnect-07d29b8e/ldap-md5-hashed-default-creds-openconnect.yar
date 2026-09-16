rule ldap_md5_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}SNGML5JTlpRpyZr644t7nA=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}SNGML5JTlpRpyZr644t7nA=="
    $a3="{MD5}GN6QxtpZ5EXXHu9qtGHKsg=="
    $a4="{MD5}SNGML5JTlpRpyZr644t7nA=="
    $a5="{MD5}T1zsdcdEvTm1Em3ru3z/uA=="
    $a6="{MD5}SNGML5JTlpRpyZr644t7nA=="
    $a7="{MD5}oYtSE0v5eaeA+E6scFePng=="
    $a8="{MD5}SNGML5JTlpRpyZr644t7nA=="
    $a9="{MD5}KIaC7F8kUFiLs3pFI9EWFg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}