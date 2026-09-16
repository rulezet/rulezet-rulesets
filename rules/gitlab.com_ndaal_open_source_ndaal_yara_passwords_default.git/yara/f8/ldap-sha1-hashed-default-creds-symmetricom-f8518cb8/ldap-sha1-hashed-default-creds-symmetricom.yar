rule ldap_sha1_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}qqyaO1Io5o/yVahGJ5zV2YM5Uto="
    $a1="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a2="{SHA}86qF73KVeGlGSxbmVdw2MiF7uNQ="
    $a3="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}