rule base64_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="cGFzc3dvcmQ="
    $a4="ZGNtYWRtaW4="
    $a5="cGFzc3cwcmQ="
    $a6="cG9zdGdyZXM="
    $a7="MTIz"
    $a8="cG9zdGdyZXM="
    $a9="YWRtaW4="
    $a10="cG9zdGdyZXM="
    $a11="YW1iZXI="
    $a12="cG9zdGdyZXM="
    $a13="cGFzc3dvcmQ="
    $a14="cG9zdGdyZXM="
    $a15="cG9zdGdyZXM="
    $a16="cG9zdGdyZXM="
    $a17="cGFzc3dvcmQgICAg"
    $a18="cG9zdGdyZXM="
    $a19="YWRtaW4g"
    $a20="YWRtaW4="
    $a21="YWRtaW4g"
    $a22="YWRtaW4="
    $a23="cGFzc3dvcmQgIA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}