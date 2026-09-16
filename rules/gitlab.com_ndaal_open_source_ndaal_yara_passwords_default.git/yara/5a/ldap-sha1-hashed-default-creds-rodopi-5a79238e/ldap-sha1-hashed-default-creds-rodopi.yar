rule ldap_sha1_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}eS+ogzWtnudKxANHPNpQsjp7wRQ="
    $a1="{SHA}eS+ogzWtnudKxANHPNpQsjp7wRQ="
    $a2="{SHA}9OZfIFnvrtY3kzLX6QEVm6uu3hI="
    $a3="{SHA}9OZfIFnvrtY3kzLX6QEVm6uu3hI="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}