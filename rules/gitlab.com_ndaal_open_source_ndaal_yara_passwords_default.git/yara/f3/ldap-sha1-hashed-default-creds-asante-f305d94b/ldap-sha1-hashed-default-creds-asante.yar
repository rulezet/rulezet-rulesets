rule ldap_sha1_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}WLTUWC3ZhR3J80r+Zli1UF0F+Uo="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}WLTUWC3ZhR3J80r+Zli1UF0F+Uo="
    $a3="{SHA}jme7JrNY4u0g/lUu1vuDLzl6UH0="
    $a4="{SHA}+0ELGKqCz/gIlx4fldK+Fd7uorw="
    $a5="{SHA}Dj1hpE62LgsuzoDQV+gm4BsZpIQ="
    $a6="{SHA}+0ELGKqCz/gIlx4fldK+Fd7uorw="
    $a7="{SHA}CKM6n4wBU9Um96E0iGOBadlua2M="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}