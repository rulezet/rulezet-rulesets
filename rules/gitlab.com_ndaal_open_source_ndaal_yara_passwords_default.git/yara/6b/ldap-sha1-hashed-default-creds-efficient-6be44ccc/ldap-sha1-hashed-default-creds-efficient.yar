rule ldap_sha1_hashed_default_creds_efficient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for efficient."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a1="{SHA}Jzb6spHwTmm2LUkMPAk2H1uCRho="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}Jzb6spHwTmm2LUkMPAk2H1uCRho="
    $a4="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a5="{SHA}jme7JrNY4u0g/lUu1vuDLzl6UH0="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}