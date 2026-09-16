rule ldap_sha1_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Kr1V4AHFJMss9jAKicpjZoSKd9U="
    $a1="{SHA}Mpy4trqMQnvnwJspgpXGVUFcesk="
    $a2="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a3="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}