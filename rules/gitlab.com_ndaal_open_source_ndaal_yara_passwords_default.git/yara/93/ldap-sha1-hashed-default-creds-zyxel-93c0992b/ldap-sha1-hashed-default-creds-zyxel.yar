rule ldap_sha1_hashed_default_creds_zyxel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a3="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a4="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a5="{SHA}MODF8OxTWfIeNK82kUcMG5GGUpU="
    $a6="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a7="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a8="{SHA}EJ6TzMi6nNqAqvccdsRp1dxi+W8="
    $a9="{SHA}hbhJVjDs3jJaKp5Q8KDkATCZgGc="
    $a10="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a11="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a12="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a13="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a14="{SHA}Od+lUoMxjTGv5aP/Sg4yU+IEXkM="
    $a15="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a16="{SHA}qvKFgCagfX9opxfamxCSNMWaKdo="
    $a17="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}