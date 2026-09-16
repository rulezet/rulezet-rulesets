rule base64_hashed_default_creds_dlink
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dlink."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW4="
    $a1="QWRtaW4="
    $a2="YWRtaW4="
    $a3="YWRtaW4="
    $a4="YWRtaW4="
    $a5="cHVibGlj"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}