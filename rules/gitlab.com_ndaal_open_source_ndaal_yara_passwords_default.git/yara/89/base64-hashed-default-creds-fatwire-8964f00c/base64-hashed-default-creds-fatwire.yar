rule base64_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Zmlyc3RzaXRl"
    $a1="Zmlyc3RzaXRl"
    $a2="ZndhZG1pbg=="
    $a3="eGNlbGFkbWlu"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}