rule ldap_sha1_hashed_default_creds_linksys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for linksys."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}P2JqL1zrjyJVNEMHOqOWFtvHdwg="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a5="{SHA}Fp4VFITtyyqqmzgEe9lzhrbByis="
    $a6="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a7="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a8="{SHA}K8RV9Hwr3ztTp6OpTYg1JPuQLzU="
    $a9="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}