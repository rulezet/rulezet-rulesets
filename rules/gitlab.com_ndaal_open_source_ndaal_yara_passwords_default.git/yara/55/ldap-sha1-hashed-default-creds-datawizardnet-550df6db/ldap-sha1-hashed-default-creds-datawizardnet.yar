rule ldap_sha1_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}oH7168QJ4QVApPSlctMUkxJrwUk="
    $a1="{SHA}CpL6syMBNMym6t2YmDJbmyrmeZg="
    $a2="{SHA}xf4CANHHpROb0Y/SImjEyov0XpA="
    $a3="{SHA}CpL6syMBNMym6t2YmDJbmyrmeZg="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}