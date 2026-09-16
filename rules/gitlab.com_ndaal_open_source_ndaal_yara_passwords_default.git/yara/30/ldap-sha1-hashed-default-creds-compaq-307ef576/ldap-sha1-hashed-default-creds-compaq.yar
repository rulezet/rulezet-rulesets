rule ldap_sha1_hashed_default_creds_compaq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for compaq."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a2="{SHA}HGmtlPMcV/4ugBk5iBRcVKe5z9s="
    $a3="{SHA}Z1Mt2qARk+OhMhM4U+aT9k6tnXI="
    $a4="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a5="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a6="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a7="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a8="{SHA}YcmysX23eieEG77qv/kjRIsPY4g="
    $a9="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a10="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a11="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a12="{SHA}GoVlqdxyBIugO0FWvj5WnyJ3HyM="
    $a13="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a14="{SHA}wfRsgFIA2ACgwBhbMzNLJj00x+0="
    $a15="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}