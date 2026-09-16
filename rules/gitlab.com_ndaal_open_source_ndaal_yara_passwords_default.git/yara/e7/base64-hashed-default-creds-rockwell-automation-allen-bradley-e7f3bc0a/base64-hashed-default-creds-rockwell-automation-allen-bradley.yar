rule base64_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW5pc3RyYXRvcg=="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="cGFzc3dvcmQ="
    $a4="dXBsb2FkZXI="
    $a5="WllQQ09N"
    $a6="cHBwX3VzZXI="
    $a7="WllQQ09N"
    $a8="Z3Vlc3Q="
    $a9="Z3Vlc3Q="
    $a10="YWRtaW5pc3RyYXRvcg=="
    $a11="bWwxNDAw"
    $a12="YWRtaW5pc3RyYXRvcg=="
    $a13="bWwxMTAw"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}