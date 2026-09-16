rule ldap_sha1_hashed_default_creds_patton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}l5aAn32uSC0xI8FlhfK2D5dAd5Y="
    $a1="{SHA}l5aAn32uSC0xI8FlhfK2D5dAd5Y="
    $a2="{SHA}jme7JrNY4u0g/lUu1vuDLzl6UH0="
    $a3="{SHA}jme7JrNY4u0g/lUu1vuDLzl6UH0="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}