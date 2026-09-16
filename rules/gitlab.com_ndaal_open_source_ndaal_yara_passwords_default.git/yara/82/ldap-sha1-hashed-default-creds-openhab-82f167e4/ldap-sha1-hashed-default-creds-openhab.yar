rule ldap_sha1_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}DSsUFpIOMKm5MndQW5Sh84592Y8="
    $a1="{SHA}DSsUFpIOMKm5MndQW5Sh84592Y8="
    $a2="{SHA}hdc6Rba4Dc5F7Bb5D2AcJhuGndM="
    $a3="{SHA}xqT+CyWnRJfpZvJ59RhsmeXOMOM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}