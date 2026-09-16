rule base64_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW5pc3RyYXRvcg=="
    $a1="MTIzNA=="
    $a2="TG9jYWxDb21TZXJ2ZXI="
    $a3="TENTIHB3ZCAwMw=="
    $a4="VFBTTG9jYWxTZXJ2ZXI="
    $a5="VExTIHB3ZCAwMw=="
    $a6="R3Vlc3Q="
    $a7="Z3Vlc3Q="
    $a8="U3lzQWRtaW4="
    $a9="aG9uZXk="
    $a10="YWRtaW4="
    $a11="YWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}