rule ldap_sha1_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a1="{SHA}xf4CANHHpROb0Y/SImjEyov0XpA="
    $a2="{SHA}vVZNtdXMNY6w41I9PgMEFznyMNU="
    $a3="{SHA}oVm3roG6NVKvYelzGyCHBRWURTg="
    $a4="{SHA}DxJUGvzOF1+zS7BaeclbdudlSIs="
    $a5="{SHA}Jzb6spHwTmm2LUkMPAk2H1uCRho="
    $a6="{SHA}vVZNtdXMNY6w41I9PgMEFznyMNU="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}