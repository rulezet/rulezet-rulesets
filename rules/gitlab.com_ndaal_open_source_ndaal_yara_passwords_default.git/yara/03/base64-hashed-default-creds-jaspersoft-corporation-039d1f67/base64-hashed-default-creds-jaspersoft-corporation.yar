rule base64_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZGVtbw=="
    $a1="ZGVtbw=="
    $a2="amFzcGVyYWRtaW4="
    $a3="amFzcGVyYWRtaW4="
    $a4="am9ldXNlcg=="
    $a5="am9ldXNlcg=="
    $a6="c3VwZXJ1c2Vy"
    $a7="c3VwZXJ1c2Vy"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}