rule base64_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="MTIzNA=="
    $a4="YWRtaW4="
    $a5="cGFzc3dvcmQ="
    $a6="YWRtaW4="
    $a7="ZGFyZWFkc2w="
    $a8="QWxwaGFuZXR3b3Jrcw=="
    $a9="d3JnZzE1X2RpNTI0"
    $a10="YWRtaW4="
    $a11="cHVibGlj"
    $a12="RC1MaW5r"
    $a13="RC1MaW5r"
    $a14="YWRtaW4="
    $a15="Z3Z0MTIzNDU="
    $a16="YWRtaW4="
    $a17="eWVhcjIwMDA="
    $a18="ZG9udCBuZWVkIG9uZQ=="
    $a19="YWRtaW4="
    $a20="cm9vdA=="
    $a21="YWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}