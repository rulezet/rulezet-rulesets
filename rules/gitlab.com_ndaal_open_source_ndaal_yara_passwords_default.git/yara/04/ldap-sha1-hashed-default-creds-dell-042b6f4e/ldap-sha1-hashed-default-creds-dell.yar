rule ldap_sha1_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}y2VKyPNvhAAW8EOqPk4GeWUpcE0="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}3HCPv2Rs1cO3P4KilGKUotH5+sQ="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a6="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}3ABPwxHtwU42hhNKHHZVhCBZ2FY="
    $a9="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a10="{SHA}lXt3tlplJsgwsXeZz4fmOe9sIw8="
    $a11="{SHA}1vdy+Id4siYm0rhioUpGFIGFd44="
    $a12="{SHA}2Oz1DQizD2jsyvw1Mrucn8xb3XU="
    $a13="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a14="{SHA}lgdjmu9+bL0qJ1fZ7+MwYijOgcE="
    $a15="{SHA}indhO0deRgZDIf19oY0SbuNeUGY="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}