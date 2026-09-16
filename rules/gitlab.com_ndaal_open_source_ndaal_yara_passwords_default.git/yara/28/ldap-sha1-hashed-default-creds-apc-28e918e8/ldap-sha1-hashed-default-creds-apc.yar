rule ldap_sha1_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a1="{SHA}ZlPO/V0t3Ewrwmt1/AnbqAsYGxM="
    $a2="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a3="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a4="{SHA}G/4VK5ZaSjvMST/ia0b98AUJ+oM="
    $a5="{SHA}u6JhcFbzrZsarr0t8QwOac9PZH0="
    $a6="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a7="{SHA}midxgpchjDdXw2XTV9E/SdD6MGU="
    $a8="{SHA}Wbe8Q4308sOXNvhK3VQDbyCD72A="
    $a9="{SHA}86kpszZLRxpIH0982gtFWezemro="
    $a10="{SHA}86kpszZLRxpIH0982gtFWezemro="
    $a11="{SHA}86kpszZLRxpIH0982gtFWezemro="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}