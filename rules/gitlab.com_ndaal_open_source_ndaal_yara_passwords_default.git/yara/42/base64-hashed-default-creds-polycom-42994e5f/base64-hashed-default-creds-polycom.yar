rule base64_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="UG9seWNvbQ=="
    $a1="NDU2"
    $a2="UG9seWNvbQ=="
    $a3="U3BJcA=="
    $a4="YWRtaW5pc3RyYXRvcg=="
    $a5="KiAqICM="
    $a6="YWRtaW4="
    $a7="YWRtaW4J"
    $a8="UG9seWNvbQ=="
    $a9="NDU2CQ=="
    $a10="YWRtaW4="
    $a11="NDU2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}