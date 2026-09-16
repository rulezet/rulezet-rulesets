rule base64_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="MTk4OA=="
    $a2="YWRtaW5pc3RyYXRvcg=="
    $a3="cGFzc3dvcmQ="
    $a4="cm9vdA=="
    $a5="bW96YXJ0"
    $a6="TmV0TGlueA=="
    $a7="cGFzc3dvcmQ="
    $a8="QWRtaW4="
    $a9="MTk4OA=="
    $a10="Z3Vlc3Q="
    $a11="Z3Vlc3Q="
    $a12="YWRtaW4="
    $a13="YWRtaW4="
    $a14="QWRtaW5pc3RyYXRvcg=="
    $a15="dmlzaW9uMg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}