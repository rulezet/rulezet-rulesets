rule base64_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3lzYWRt"
    $a1="c3lzYWRt"
    $a2="ZGVidWc="
    $a3="ZC5lLmIudS5n"
    $a4="Z3Vlc3Q="
    $a5="Z3Vlc3Q="
    $a6="TWFuYWdlcg=="
    $a7="QWRtaW4="
    $a8="ZC5lLmIudS5n"
    $a9="VXNlcg=="
    $a10="ZWNobw=="
    $a11="VXNlcg=="
    $a12="Z3Vlc3Q="
    $a13="VXNlcg=="
    $a14="c3lzYWRt"
    $a15="QWRtaW4="
    $a16="TWFuYWdlcg=="
    $a17="TWFuYWdlcg=="
    $a18="ZWNobw=="
    $a19="ZWNobw=="
    $a20="MTUwMA=="
    $a21="YW5kIDIwMDAgU2VyaWVz"
    $a22="d3JpdGU="
    $a23="cHJpdmF0ZQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}