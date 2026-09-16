rule ldap_sha1_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a1="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a2="{SHA}gk9gHCqB7mureczUeSMExzjRdjA="
    $a3="{SHA}gk9gHCqB7mureczUeSMExzjRdjA="
    $a4="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a5="{SHA}gk9gHCqB7mureczUeSMExzjRdjA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}