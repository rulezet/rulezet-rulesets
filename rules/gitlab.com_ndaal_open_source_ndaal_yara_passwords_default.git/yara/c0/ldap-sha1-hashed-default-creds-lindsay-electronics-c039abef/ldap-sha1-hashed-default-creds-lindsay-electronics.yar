rule ldap_sha1_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}H9pEg+DS1uk6oqQOAXOTIwUbq0s="
    $a1="{SHA}JcXRhP08jn0krw4jfAYfVICl6G4="
    $a2="{SHA}H9pEg+DS1uk6oqQOAXOTIwUbq0s="
    $a3="{SHA}H9pEg+DS1uk6oqQOAXOTIwUbq0s="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}