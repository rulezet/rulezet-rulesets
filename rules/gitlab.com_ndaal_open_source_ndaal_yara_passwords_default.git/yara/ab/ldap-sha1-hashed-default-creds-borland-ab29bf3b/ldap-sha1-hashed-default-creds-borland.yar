rule ldap_sha1_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}MXmmXv8lI7veU8mbKZtxnBCjUjU="
    $a1="{SHA}Tj4FJZqym2w36YOnPJm/h02izZo="
    $a2="{SHA}MXmmXv8lI7veU8mbKZtxnBCjUjU="
    $a3="{SHA}BqFO0ckYkBX3XdeWBjNN6pZQoRY="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}