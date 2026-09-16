rule sha224_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9468b5307d3514f902f81af5ee8a488bd244ed4c1bdc02d6f17f63aa"
    $a1="3a94f0a636b4a3f7eeb1242137904293f054a0038b12321675543356"
    $a2="3a94f0a636b4a3f7eeb1242137904293f054a0038b12321675543356"
    $a3="3a94f0a636b4a3f7eeb1242137904293f054a0038b12321675543356"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}