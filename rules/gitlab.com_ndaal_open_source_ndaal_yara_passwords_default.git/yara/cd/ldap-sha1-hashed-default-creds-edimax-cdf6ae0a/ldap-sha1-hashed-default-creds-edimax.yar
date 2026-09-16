rule ldap_sha1_hashed_default_creds_edimax
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}QL0AFWMIX8NRZTKeof9cXsvbvu8="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}PPRY10X2qwRLVmQ4JnhimzwISEo="
    $a7="{SHA}uraKPmEVp7JSxbZ9Q48zAqNS4W0="
    $a8="{SHA}GxD+jB8vXCn3j6r6Umr9IQ3tn7I="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a10="{SHA}PHEUYvdIfIcF16NZ8fudjxeVGMU="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a12="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a13="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}