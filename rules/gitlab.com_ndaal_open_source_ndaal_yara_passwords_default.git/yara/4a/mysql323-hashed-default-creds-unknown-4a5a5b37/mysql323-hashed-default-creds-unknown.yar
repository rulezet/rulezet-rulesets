rule mysql323_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76779e856ee86156"
    $a1="76779e856ee86156"
    $a2="4297dfd67bfb01dd"
    $a3="4297dfd67bfb01dd"
    $a4="378b243e220ca493"
    $a5="378b243e220ca493"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}