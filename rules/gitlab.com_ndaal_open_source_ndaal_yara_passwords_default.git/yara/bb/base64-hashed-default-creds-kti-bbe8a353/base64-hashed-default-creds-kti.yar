rule base64_hashed_default_creds_kti
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kti."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3VwZXJ1c2Vy"
    $a1="MTIzNDU2"
    $a2="YWRtaW4="
    $a3="MTIz"
    $a4="YWRtaW4="
    $a5="MTIzNDU2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}