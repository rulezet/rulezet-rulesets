rule ldap_sha1_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a1="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a2="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a3="{SHA}86kpszZLRxpIH0982gtFWezemro="
    $a4="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a5="{SHA}midxgpchjDdXw2XTV9E/SdD6MGU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}