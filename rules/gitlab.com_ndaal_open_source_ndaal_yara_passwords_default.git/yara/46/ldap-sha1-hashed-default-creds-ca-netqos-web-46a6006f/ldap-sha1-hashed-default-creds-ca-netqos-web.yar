rule ldap_sha1_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0SIDG0X4PNiJQR8/qMgCAolHlHo="
    $a1="{SHA}oMA/L7gROC2UBuo/5aYdqQR2CI8="
    $a2="{SHA}0SIDG0X4PNiJQR8/qMgCAolHlHo="
    $a3="{SHA}/LjAsbOHFeG5x3WLD5OXaq/2XF0="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}