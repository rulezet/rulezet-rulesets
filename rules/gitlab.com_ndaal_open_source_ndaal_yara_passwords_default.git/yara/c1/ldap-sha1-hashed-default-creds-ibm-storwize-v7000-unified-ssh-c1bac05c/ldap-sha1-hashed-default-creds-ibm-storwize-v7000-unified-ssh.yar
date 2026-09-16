rule ldap_sha1_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}JVAH/iXwoFy5rk5Jy2Ov5AdDw0E="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}6/x5EAd3cMg0D2PNLcoqwfEgRE8="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a4="{SHA}fGphxo74ubawYbKMNIvB7Xkhy1M="
    $a5="{SHA}jme7JrNY4u0g/lUu1vuDLzl6UH0="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}