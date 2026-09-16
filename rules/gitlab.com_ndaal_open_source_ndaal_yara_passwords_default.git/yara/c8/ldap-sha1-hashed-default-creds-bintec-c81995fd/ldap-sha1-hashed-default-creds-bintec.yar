rule ldap_sha1_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}JoxH+EPZPFhID2foTFTQdVMD9k4="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}GSRaR/c6G9u1m6vFLYJm/HXXx74="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}gWxS/SvdlKY80JRII6bAqpOEwQM="
    $a5="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}