rule ldap_md5_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Y9AsNumDwvU2XHSztab7KQ=="
    $a1="{MD5}Y9AsNumDwvU2XHSztab7KQ=="
    $a2="{MD5}NRMlpmCyVHRFavXJpWBsTg=="
    $a3="{MD5}NRMlpmCyVHRFavXJpWBsTg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}