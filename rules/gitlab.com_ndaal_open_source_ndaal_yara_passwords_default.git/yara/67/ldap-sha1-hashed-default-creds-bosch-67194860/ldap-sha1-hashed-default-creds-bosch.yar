rule ldap_sha1_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}TPW8Wb7p4cRMYlS1+E5/BmvY5f4="
    $a1="{SHA}TPW8Wb7p4cRMYlS1+E5/BmvY5f4="
    $a2="{SHA}mKrbNwg+3dhVwn/syxXcjFsSf9A="
    $a3="{SHA}mKrbNwg+3dhVwn/syxXcjFsSf9A="
    $a4="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a5="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}