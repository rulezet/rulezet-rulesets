rule ldap_sha1_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a2="{SHA}NVm85iZiWcYcDoqkP10gkZj1FuE="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}NVm85iZiWcYcDoqkP10gkZj1FuE="
    $a5="{SHA}NVm85iZiWcYcDoqkP10gkZj1FuE="
    $a6="{SHA}2ODkvBcvRzlPccbEMUdew3uIPE0="
    $a7="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a8="{SHA}GNn2o/pamf7gz5cF99qtQ1YhBx8="
    $a9="{SHA}mhmMnwNrc4OZW/o+MFHs/7UG/ZU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}