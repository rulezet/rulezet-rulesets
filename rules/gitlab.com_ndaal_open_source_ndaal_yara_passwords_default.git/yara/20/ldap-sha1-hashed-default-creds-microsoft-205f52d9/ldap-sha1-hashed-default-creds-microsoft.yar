rule ldap_sha1_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a1="{SHA}d4mzcug02HUp9oqoe4ZHJrtpnHo="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a5="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a6="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a7="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a8="{SHA}+s6D7jAUvcj5ggPMlOLokiJFLpA="
    $a9="{SHA}+s6D7jAUvcj5ggPMlOLokiJFLpA="
    $a10="{SHA}LM6BZM+UFHJgAQs7kWFBNYLMqcM="
    $a11="{SHA}LM6BZM+UFHJgAQs7kWFBNYLMqcM="
    $a12="{SHA}jrZiFZeNk/WLTbcBX7bpgfGGbj8="
    $a13="{SHA}/qCP/I1GrRIDQaSNOPWV2S1r5RY="
    $a14="{SHA}/llLifJ4ZGzDzlmSvIhFGMET4p4="
    $a15="{SHA}/llLifJ4ZGzDzlmSvIhFGMET4p4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}