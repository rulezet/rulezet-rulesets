rule ldap_sha1_hashed_default_creds_polycom_vvx_500_phone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom_vvx_500_phone."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}UerGtHGihNM0HYwMY9DxooYmKhg="
    $a1="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a2="{SHA}QL0AFWMIX8NRZTKeof9cXsvbvu8="
    $a3="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}