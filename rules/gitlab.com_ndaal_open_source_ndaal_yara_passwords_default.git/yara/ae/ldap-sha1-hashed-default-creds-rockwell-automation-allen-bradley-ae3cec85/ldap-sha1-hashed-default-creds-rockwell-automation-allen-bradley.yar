rule ldap_sha1_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}0B2LPOuZ1huGuUuGkTp67WvNeZo="
    $a5="{SHA}Qa6M9/Hsft+MfMH3foAFk+FKomU="
    $a6="{SHA}0B2LPOuZ1huGuUuGkTp67WvNeZo="
    $a7="{SHA}5N0/xUmpktk0ua7MDTfAmMVMzrc="
    $a8="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a9="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a10="{SHA}o6IojozCfOqPcC8srrGVdo5SjAo="
    $a11="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a12="{SHA}BfCwdGmrGvkqNmB66UdSSeKIs7Q="
    $a13="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}