rule base64_hashed_default_creds_efficient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for efficient."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bG9naW4="
    $a1="cGFzc3dvcmQ="
    $a2="bG9naW4="
    $a3="YWRtaW4="
    $a4="c3VwZXJ1c2Vy"
    $a5="YWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}