rule ldap_sha1_hashed_default_creds_fortinet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}hkFu8+60zJB+vNEsAwVRG0z8VHQ="
    $a2="{SHA}PjSSJN0jhZnIvge1jEbHp1HnNXs="
    $a3="{SHA}hkFu8+60zJB+vNEsAwVRG0z8VHQ="
    $a4="{SHA}+B7E/nh5yabQa3IEQX8wl9cn/W0="
    $a5="{SHA}hkFu8+60zJB+vNEsAwVRG0z8VHQ="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}