rule ldap_sha1_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}dF0LI4DiE1PVJttHqHFY8gZVY+4="
    $a1="{SHA}r8hIwxavGonUmCbFrp0A7XaUFfM="
    $a2="{SHA}92wYkYzHX7ac4pkzihPyQnjdvvE="
    $a3="{SHA}r8hIwxavGonUmCbFrp0A7XaUFfM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}