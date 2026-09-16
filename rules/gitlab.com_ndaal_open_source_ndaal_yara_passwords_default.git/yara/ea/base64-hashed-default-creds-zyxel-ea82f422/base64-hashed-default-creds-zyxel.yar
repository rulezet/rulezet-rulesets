rule base64_hashed_default_creds_zyxel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="MTIzNA=="
    $a2="MTIzNA=="
    $a3="MTIzNA=="
    $a4="d2ViYWRtaW4="
    $a5="MTIzNA=="
    $a6="cm9vdA=="
    $a7="MTIzNA=="
    $a8="MTkyLjE2OC4xLjEgNjAwMjA="
    $a9="QGRzbF94aWxubw=="
    $a10="MTIzNA=="
    $a11="QWRtaW5pc3RyYXRvcg=="
    $a12="YWRtaW4="
    $a13="YWRtaW4="
    $a14="YWRtaW4="
    $a15="MDAwMA=="
    $a16="QWRtaW4="
    $a17="YXRjNDU2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}