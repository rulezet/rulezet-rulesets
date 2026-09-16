rule ldap_sha1_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a4="{SHA}cXQYmfIqAMcu5PdMYTRwZktuJBw="
    $a5="{SHA}cXQYmfIqAMcu5PdMYTRwZktuJBw="
    $a6="{SHA}Yv2+Ic9h9jcZHZcauaXKulEJSqc="
    $a7="{SHA}EP/mDVPncDKG6qtCHwXJRv+hmjc="
    $a8="{SHA}tkl6CtcVOEQySL3jQgy72jlf3gA="
    $a9="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a10="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a11="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a12="{SHA}WYNurGQZV5ZoihF4DfXE4s5mi5U="
    $a13="{SHA}WYNurGQZV5ZoihF4DfXE4s5mi5U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}