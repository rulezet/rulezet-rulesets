rule ldap_sha1_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}CHcjUbh419NmMZVcAX/VMHnCRFs="
    $a1="{SHA}jxmPrYXBreLB+ldRWHJmcteJ7uo="
    $a2="{SHA}7ONid1ADqizEUu0A08H6Xg9793o="
    $a3="{SHA}jxmPrYXBreLB+ldRWHJmcteJ7uo="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}