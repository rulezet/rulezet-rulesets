rule ldap_sha1_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}pgocep1ogiPZSOg+aiy0DNfIPzs="
    $a1="{SHA}pgocep1ogiPZSOg+aiy0DNfIPzs="
    $a2="{SHA}1EKU2rtVWdg0+PjRxdT9dcFldw4="
    $a3="{SHA}1EKU2rtVWdg0+PjRxdT9dcFldw4="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}