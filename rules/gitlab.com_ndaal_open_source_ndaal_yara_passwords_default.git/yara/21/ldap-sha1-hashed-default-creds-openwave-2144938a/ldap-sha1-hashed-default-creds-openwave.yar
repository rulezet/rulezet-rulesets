rule ldap_sha1_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}PImEmgBZQ+K+JCzIIM3D+Hp61Hw="
    $a1="{SHA}i80NeT5cJNP75vLNc/PciWJpbbk="
    $a2="{SHA}gcZOFW9d0mfQ3z0JNAmXcaEXG4E="
    $a3="{SHA}tMVu6NKFQWbexmZE9UG4UkcQWyw="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}