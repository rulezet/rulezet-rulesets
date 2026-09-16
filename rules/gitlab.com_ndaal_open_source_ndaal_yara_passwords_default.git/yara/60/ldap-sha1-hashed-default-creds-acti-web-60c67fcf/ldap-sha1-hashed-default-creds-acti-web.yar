rule ldap_sha1_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a3="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a4="{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs="
    $a7="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}