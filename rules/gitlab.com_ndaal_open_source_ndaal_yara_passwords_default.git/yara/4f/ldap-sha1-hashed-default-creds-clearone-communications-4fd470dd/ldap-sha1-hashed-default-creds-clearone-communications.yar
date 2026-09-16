rule ldap_sha1_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}GrMoB5bUJILbmcVWZZc4vQXyrEY="
    $a1="{SHA}8w742vUrtLf6zrqJyTg6agd1ZRw="
    $a2="{SHA}5+TGvhKA0SvJsrdVA38O6IC9Lbw="
    $a3="{SHA}gcna3eeTb31dGHfgKHoETDaVQ5c="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}