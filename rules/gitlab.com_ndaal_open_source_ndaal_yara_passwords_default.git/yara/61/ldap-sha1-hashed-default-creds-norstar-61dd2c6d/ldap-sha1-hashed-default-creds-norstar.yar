rule ldap_sha1_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}C8N8qbmvUEoTRfdIAgg8D1dZjNg="
    $a1="{SHA}zMhV50i7NC/77bHCuYAJ1c3z+hg="
    $a2="{SHA}e3mXn5J2CoZqEPQ8dPs37WAT5II="
    $a3="{SHA}ISm2ZBOwUFAPVjJ9dk15o8WQYHg="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}