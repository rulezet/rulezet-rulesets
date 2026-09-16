rule ldap_sha1_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}O1u0kmpEyJWgU1dl4WGNYMmQHiI="
    $a1="{SHA}O1u0kmpEyJWgU1dl4WGNYMmQHiI="
    $a2="{SHA}CWFGpm928oUNZSfhTfsfrYmFRpo="
    $a3="{SHA}178ingGyHgxSHLgLJr8kvQ8dcts="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}