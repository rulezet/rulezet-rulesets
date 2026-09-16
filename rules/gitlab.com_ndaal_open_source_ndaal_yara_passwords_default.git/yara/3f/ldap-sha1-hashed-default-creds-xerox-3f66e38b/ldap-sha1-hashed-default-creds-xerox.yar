rule ldap_sha1_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}PyJ+pWWiGVYeJTvfrdu/uk987T0="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}GpuVCLYAO2jd/gOpyMvEvUOIM5s="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}/qf2V/VqKkSNp9S1Ne5eJ5yvPZo="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}PyJ+pWWiGVYeJTvfrdu/uk987T0="
    $a9="{SHA}eyGEismvNb4N2y1rn8OFGTTbhCA="
    $a10="{SHA}ARyUXzDOLLr8RS85hA8CVpMznEI="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a12="{SHA}IJRqXpBwZDb8b9I6jkwq5WJAFyU="
    $a13="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a14="{SHA}YGGGNiP4Btfbesj6j543C7vpwJU="
    $a15="{SHA}Ifv40ulXd7npPd9Gr8KUU/gjNaw="
    $a16="{SHA}L8fxRSN0tuNB1ncX8DKrvg2g9KY="
    $a17="{SHA}4sYk5k1H/CgYRd/CDCxV8VLIwUA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}