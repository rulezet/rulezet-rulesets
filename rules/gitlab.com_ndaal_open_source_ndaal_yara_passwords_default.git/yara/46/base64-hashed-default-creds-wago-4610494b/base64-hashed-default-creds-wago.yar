rule base64_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="d2Fnbw=="
    $a2="dXNlcg=="
    $a3="dXNlcg=="
    $a4="Z3Vlc3Q="
    $a5="Z3Vlc3Q="
    $a6="dXNlcg=="
    $a7="dXNlcjAw"
    $a8="c3U="
    $a9="a28yMDAzd2E="
    $a10="cm9vdA=="
    $a11="d2Fnbw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}