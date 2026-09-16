rule ldap_md5_hashed_default_creds_red_hat_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for red_hat_inc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}8RkD2HC9UTb99y0iZe95Ug=="
    $a3="{MD5}8RkD2HC9UTb99y0iZe95Ug=="
    $a4="{MD5}dpT0pmMW5TyM3Z2ZVL1hHQ=="
    $a5="{MD5}8RkD2HC9UTb99y0iZe95Ug=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}