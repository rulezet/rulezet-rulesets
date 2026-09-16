rule ldap_md5_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}0QRY9yJfXh5WIrDivNuOpA=="
    $a1="{MD5}0QRY9yJfXh5WIrDivNuOpA=="
    $a2="{MD5}YkGZfqztIX2TFLsJGVfbSQ=="
    $a3="{MD5}FytQSOjTG7Mjb78fZJ3Xaw=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}