rule base64_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cm9vdA=="
    $a1="Y2Fsdmlu"
    $a2="YWRtaW4="
    $a3="cGFzc3dvcmQ="
    $a4="cm9vdA=="
    $a5="cG93ZXJhcHA="
    $a6="YWRtaW4="
    $a7="YWRtaW4="
    $a8="QWRtaW5pc3RyYXRvcg=="
    $a9="c3RvcmFnZXNlcnZlcg=="
    $a10="cmFwcG9ydA=="
    $a11="ckBwOHAwcis="
    $a12="cm9vdA=="
    $a13="d3lzZQ=="
    $a14="Vk5D"
    $a15="d2ludGVybQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}