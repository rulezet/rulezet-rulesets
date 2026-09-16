rule ldap_sha1_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}jsy2zs+hGdoGODNCuskgzrMvcDI="
    $a1="{SHA}+FF6WZJfUgJzbYRfXn/ZEg80X68="
    $a2="{SHA}jsy2zs+hGdoGODNCuskgzrMvcDI="
    $a3="{SHA}FiHIGxxU9rji+t8LyjVzdHJhuv8="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}