rule ldap_sha1_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}6dcfXufJLW3J6S/9rRe4vUlBj5g="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}hvfkN/qlp/zhXR3cuerq6jd2Z7g="
    $a3="{SHA}n1bZspK1UWLKOZm1bwVLQHoq5n4="
    $a4="{SHA}6dcfXufJLW3J6S/9rRe4vUlBj5g="
    $a5="{SHA}PXNGFAAW36QMdw+hm6ciry60gHM="
    $a6="{SHA}PDY4Ns9OFmZmaaJdooChhlwtKHQ="
    $a7="{SHA}63v0IKKuHyqr2os0PH2aQRnj63Y="
    $a8="{SHA}B8NCvm5WDn9DhC4uIbd05h2F8Ec="
    $a9="{SHA}XmpPFxoq4K1DsVicRuyInO9zCq4="
    $a10="{SHA}aw0xwNVjIjAk2kVpFYRkOseMlug="
    $a11="{SHA}ItZpVMooDZWZSXsoUS+3mZ8/3RM="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}