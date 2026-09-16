rule ldap_sha1_hashed_default_creds_questra_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for questra_corporation."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a1="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a2="{SHA}fGfHaeW6W15wDjmgswDigQHcBGg="
    $a3="{SHA}fGfHaeW6W15wDjmgswDigQHcBGg="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}