rule base64_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cm9vdA=="
    $a1="cGFzc3dvcmQ="
    $a2="SEVMTE8="
    $a3="T1AuT1BFUkFUT1I="
    $a4="TUdS"
    $a5="SVRGMzAwMA=="
    $a6="TUdS"
    $a7="TkVUQkFTRQ=="
    $a8="YWRtaW4="
    $a9="aXNlZQ=="
    $a10="RmFjdG9yeQ=="
    $a11="NTY3ODk="
    $a12="QWRtaW5pc3RyYXRvcg=="
    $a13="YWRtaW4="
    $a14="YWRtaW4="
    $a15="YWRtaW4="
    $a16="YWRtaW4="
    $a17="IWFkbWlu"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}