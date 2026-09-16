rule ldap_sha1_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}2z1AWxBnWZjAMCIxd9QucbTnoxI="
    $a3="{SHA}2z1AWxBnWZjAMCIxd9QucbTnoxI="
    $a4="{SHA}w8nOGdxcD9hTwwvIJSYR05gf+cY="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a6="{SHA}jfKuBmghi3SCLabn3k0YtngjC9Y="
    $a7="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a8="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a9="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a10="{SHA}041vADufHOgZCjqzpPsjStgREH8="
    $a11="{SHA}041vADufHOgZCjqzpPsjStgREH8="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}