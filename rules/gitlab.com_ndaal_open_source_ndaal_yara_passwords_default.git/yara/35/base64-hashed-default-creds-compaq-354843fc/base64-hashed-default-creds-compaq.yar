rule base64_hashed_default_creds_compaq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for compaq."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW5pc3RyYXRvcg=="
    $a1="YWRtaW4="
    $a2="UEZDVXNlcg=="
    $a3="MjQwNjUzQzk0NjdFNDU="
    $a4="YWRtaW5pc3RyYXRvcg=="
    $a5="YWRtaW5pc3RyYXRvcg=="
    $a6="b3BlcmF0b3I="
    $a7="b3BlcmF0b3I="
    $a8="dXNlcg=="
    $a9="cHVibGlj"
    $a10="dXNlcg=="
    $a11="dXNlcg=="
    $a12="cm9vdA=="
    $a13="bWFuYWdlcg=="
    $a14="cm9vdA=="
    $a15="cm9vdG1l"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}