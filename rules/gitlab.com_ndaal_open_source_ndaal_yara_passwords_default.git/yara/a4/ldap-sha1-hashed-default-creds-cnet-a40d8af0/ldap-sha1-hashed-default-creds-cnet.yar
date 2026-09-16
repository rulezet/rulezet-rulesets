rule ldap_sha1_hashed_default_creds_cnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cnet."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}GxD+jB8vXCn3j6r6Umr9IQ3tn7I="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a5="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a6="{SHA}GxD+jB8vXCn3j6r6Umr9IQ3tn7I="
    $a7="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a8="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}