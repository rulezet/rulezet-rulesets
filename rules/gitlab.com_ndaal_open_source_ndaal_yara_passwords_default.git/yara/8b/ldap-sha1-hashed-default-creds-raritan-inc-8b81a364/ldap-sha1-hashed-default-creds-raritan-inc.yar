rule ldap_sha1_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}nNtkqxHQ/bMRFpFzySAXZpVW714="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}nNtkqxHQ/bMRFpFzySAXZpVW714="
    $a3="{SHA}infhsSGiZILbkOeHVwTVaKi7y4M="
    $a4="{SHA}MKXYBzEivg/Ys3pvsG63NHXlAmA="
    $a5="{SHA}Z3G5Kw4Gir8oXvxoEBF/c8CxU2c="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}