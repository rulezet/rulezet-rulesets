rule base64_hashed_default_creds_pirelli
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pirelli."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="bWljcm9idXNpbmVzcw=="
    $a2="dXNlcg=="
    $a3="cGFzc3dvcmQ="
    $a4="YWRtaW4="
    $a5="YWRtaW4="
    $a6="YWRtaW4="
    $a7="c21hbGxidXNpbmVzcw=="
    $a8="YWRtaW4="
    $a9="bXU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}