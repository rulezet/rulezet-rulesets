rule ldap_sha1_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}5phnyn1aewq2Ciph57eRwQb3v2Q="
    $a1="{SHA}GoVlqdxyBIugO0FWvj5WnyJ3HyM="
    $a2="{SHA}r44+AE/Suhq//Sg9RED9Xp9zigc="
    $a3="{SHA}r44+AE/Suhq//Sg9RED9Xp9zigc="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}