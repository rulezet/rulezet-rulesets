rule ldap_sha1_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}CpL6syMBNMym6t2YmDJbmyrmeZg="
    $a1="{SHA}CpL6syMBNMym6t2YmDJbmyrmeZg="
    $a2="{SHA}22nWY1w7EJNN7mvXQl6H5jf3OzM="
    $a3="{SHA}95My7Phdi6Ks0qG2F8H8Nm7Yysw="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}