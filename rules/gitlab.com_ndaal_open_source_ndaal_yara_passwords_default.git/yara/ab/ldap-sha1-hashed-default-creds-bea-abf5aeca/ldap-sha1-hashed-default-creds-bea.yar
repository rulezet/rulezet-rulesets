rule ldap_sha1_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a1="{SHA}FqmlTd9CWZUuPBGMdjE46DaT1/0="
    $a2="{SHA}jux7xGGAjguKKHg9C+waOiLrCCE="
    $a3="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a4="{SHA}65szVNxFtj2EVicUi3ePTD1UgxE="
    $a5="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}