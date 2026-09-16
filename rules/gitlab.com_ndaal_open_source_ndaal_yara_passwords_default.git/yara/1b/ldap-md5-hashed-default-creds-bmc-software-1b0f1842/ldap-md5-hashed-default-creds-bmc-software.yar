rule ldap_md5_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}qh148wiMDbug8A7a5zwB+w=="
    $a1="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a2="{MD5}A1Kkg28FFFBZTE1oJ3o1KQ=="
    $a3="{MD5}DdQ5z493EQkIqJfRqt/Nhg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}