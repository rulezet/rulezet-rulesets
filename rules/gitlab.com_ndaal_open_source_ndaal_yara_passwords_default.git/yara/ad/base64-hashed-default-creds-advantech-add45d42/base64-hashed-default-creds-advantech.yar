rule base64_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWR2YW50ZWNo"
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="YWRtaW4="
    $a4="cm9vdA=="
    $a5="MDAwMDAwMDA="
    $a6="Um9vdA=="
    $a7="MDAwMDAwMDA="
    $a8="QWRtaW4="
    $a9="MDAwMDAwMDA="
    $a10="VXNlcg=="
    $a11="MDAwMDAwMDA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}