rule ldap_md5_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}KU3jVX2dALPS2KHmqrAozw=="
    $a1="{MD5}KU3jVX2dALPS2KHmqrAozw=="
    $a2="{MD5}qv3h2cjVM1KOSCG2gfgKGQ=="
    $a3="{MD5}O6FLxhSKDwpvy7oVfleKww=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}