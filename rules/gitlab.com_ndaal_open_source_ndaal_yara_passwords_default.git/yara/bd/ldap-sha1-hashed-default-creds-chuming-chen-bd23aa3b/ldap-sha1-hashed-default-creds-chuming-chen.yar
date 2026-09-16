rule ldap_sha1_hashed_default_creds_chuming_chen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for chuming_chen."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}dJE/XNX2HsC8/bd1QUwvs9FhtiA="
    $a1="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
condition:
    ($a0 and $a1)
}