rule ldap_sha1_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}tyy/hBlME7DCTYch1f1PmazxeyE="
    $a2="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}cDUvQQYe2k/zwyIJSvBounDDs4s="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a6="{SHA}cDUvQQYe2k/zwyIJSvBounDDs4s="
    $a7="{SHA}6WhXxY9xYQTK6tZI7mqmGrjkHNw="
    $a8="{SHA}cDUvQQYe2k/zwyIJSvBounDDs4s="
    $a9="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a10="{SHA}cDUvQQYe2k/zwyIJSvBounDDs4s="
    $a11="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}