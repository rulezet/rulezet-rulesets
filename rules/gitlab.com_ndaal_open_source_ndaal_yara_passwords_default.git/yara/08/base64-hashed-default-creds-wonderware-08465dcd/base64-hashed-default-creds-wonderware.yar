rule base64_hashed_default_creds_wonderware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW5pc3RyYXRvcg=="
    $a1="V29uZGVyd2FyZQ=="
    $a2="YWFkYm8="
    $a3="cHdkZGJv"
    $a4="d3dkYm8="
    $a5="cHdkZGJv"
    $a6="YWFBZG1pbg=="
    $a7="cHdBZG1pbg=="
    $a8="d3dBZG1pbg=="
    $a9="d3dBZG1pbg=="
    $a10="YWFQb3dlcg=="
    $a11="cHdQb3dlcg=="
    $a12="d3dQb3dlcg=="
    $a13="d3dQb3dlcg=="
    $a14="YWFVc2Vy"
    $a15="cHdVc2Vy"
    $a16="d3dVc2Vy"
    $a17="d3dVc2Vy"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}