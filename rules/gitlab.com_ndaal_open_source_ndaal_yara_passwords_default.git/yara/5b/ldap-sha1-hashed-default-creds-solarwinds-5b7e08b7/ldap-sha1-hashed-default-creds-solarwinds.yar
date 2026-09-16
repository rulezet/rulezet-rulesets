rule ldap_sha1_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Q5XfprSa2D5QcmjhDN6Zonx28IU="
    $a1="{SHA}lnjlRiD424JAa5T6DIKxh8E2xUo="
    $a2="{SHA}8B2XLOUMn8nuaeX+uHrtA6nHAgI="
    $a3="{SHA}8B2XLOUMn8nuaeX+uHrtA6nHAgI="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}