rule ldap_sha1_hashed_default_creds_accton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}GoVlqdxyBIugO0FWvj5WnyJ3HyM="
    $a1="{SHA}GoVlqdxyBIugO0FWvj5WnyJ3HyM="
    $a2="{SHA}l5aAn32uSC0xI8FlhfK2D5dAd5Y="
    $a3="{SHA}l5aAn32uSC0xI8FlhfK2D5dAd5Y="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}