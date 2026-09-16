rule base64_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cm9vdA=="
    $a1="ZnJvb3Q="
    $a2="Y2FyZWw="
    $a3="ZmNhcmVs"
    $a4="Z3Vlc3Q="
    $a5="Zmd1ZXN0"
    $a6="aHR0cGFkbWlu"
    $a7="Zmh0dHBhZG1pbg=="
    $a8="YWRtaW4="
    $a9="ZmFkbWlu"
    $a10="YWRtaW4="
    $a11="YWRtaW4="
    $a12="UFZSZW1vdGU="
    $a13="UEQzNTAxMA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}