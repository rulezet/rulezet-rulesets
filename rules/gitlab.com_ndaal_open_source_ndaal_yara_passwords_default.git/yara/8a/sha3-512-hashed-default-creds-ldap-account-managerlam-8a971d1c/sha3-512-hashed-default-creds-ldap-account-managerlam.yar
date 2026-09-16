rule sha3_512_hashed_default_creds_ldap_account_managerlam
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ldap_account_managerlam."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="674e108fad0b50c3c50da6665568c00a3a740302f0eb5a64e86583b9d22567fd3d0420d8bbfa9d394382518192f2b9575f66fc949936439347e48ebad257d9a6"
    $a1="674e108fad0b50c3c50da6665568c00a3a740302f0eb5a64e86583b9d22567fd3d0420d8bbfa9d394382518192f2b9575f66fc949936439347e48ebad257d9a6"
condition:
    ($a0 and $a1)
}