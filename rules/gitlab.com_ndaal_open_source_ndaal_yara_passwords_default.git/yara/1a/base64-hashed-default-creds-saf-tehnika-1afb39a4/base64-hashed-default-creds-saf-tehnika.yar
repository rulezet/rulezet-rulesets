rule base64_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW5pc3RyYXRvcg=="
    $a1="ZDFzY292ZXJ5"
    $a2="aW50ZWdyYXRvcg=="
    $a3="cDFuYWNhdGU="
    $a4="bW9uaXRvcg=="
    $a5="bW9uaXRvcg=="
    $a6="b3BlcmF0b3I="
    $a7="Y29sMW1h"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}