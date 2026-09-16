rule ldap_sha1_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}e5Aub/Hbn1YEQ/IEiXT9fThpdbA="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}c900K5xpMBLvyXDLjN2M91CdAOc="
    $a3="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a4="{SHA}9FlAgI4IaNHcj5jF5KHa0twhVwU="
    $a5="{SHA}Tyaur9sjZ2IKOTyXPt2+j4uEbr0="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}