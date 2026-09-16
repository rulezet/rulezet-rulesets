rule ldap_sha1_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}93UWZEodOjCEGUzul+j66dHGr5Q="
    $a1="{SHA}93UWZEodOjCEGUzul+j66dHGr5Q="
    $a2="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a3="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a4="{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M="
    $a5="{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}