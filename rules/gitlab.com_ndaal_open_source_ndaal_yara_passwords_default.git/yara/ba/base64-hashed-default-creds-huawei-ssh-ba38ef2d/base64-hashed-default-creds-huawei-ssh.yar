rule base64_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="QWRtaW4="
    $a3="YWRtaW4="
    $a4="ZGlnaWNlbA=="
    $a5="ZGlnaWNlbA=="
    $a6="dGVsZWNvbWFkbWlu"
    $a7="YWRtaW50ZWxlY29t"
    $a8="dXNlcg=="
    $a9="SHVhd2VpVXNlcg=="
    $a10="dXNlcg=="
    $a11="dXNlcg=="
    $a12="dm9kYWZvbmU="
    $a13="dm9kYWZvbmU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}