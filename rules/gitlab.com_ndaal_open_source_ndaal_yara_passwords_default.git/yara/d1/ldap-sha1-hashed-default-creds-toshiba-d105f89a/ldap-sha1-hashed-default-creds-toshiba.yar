rule ldap_sha1_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs="
    $a1="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a2="{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}zeGJy+wIOqrTHYkL6UuKaNRj/Xo="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a6="{SHA}Fv9QS3bnUhzjVgCoDhRoCmEbl7U="
    $a7="{SHA}hFG6ihTXl1PTTLM7UbpGtLAl64E="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}