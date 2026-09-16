rule ldap_sha1_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}gEN6RKZh0UEXQgkRnVQSWlmmSyo="
    $a1="{SHA}gEN6RKZh0UEXQgkRnVQSWlmmSyo="
    $a2="{SHA}0Ybo2sSKJNARW1aNCrLJ6Lguats="
    $a3="{SHA}yFgkdXo3PJjRe1a06ppWScW8tV8="
    $a4="{SHA}xvzZlVm3uGJvYiB0F4VB5M1PbNA="
    $a5="{SHA}yFgkdXo3PJjRe1a06ppWScW8tV8="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}