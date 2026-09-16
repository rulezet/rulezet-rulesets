rule ldap_md5_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}N9KYAhLFBIrZ4U26qAc9ew=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}3Ush6e9x4SkRg6RrkTrm8g=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a6="{MD5}3Ush6e9x4SkRg6RrkTrm8g=="
    $a7="{MD5}+gPraIrYqh21k9M9q9ibrQ=="
    $a8="{MD5}3Ush6e9x4SkRg6RrkTrm8g=="
    $a9="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a10="{MD5}3Ush6e9x4SkRg6RrkTrm8g=="
    $a11="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}