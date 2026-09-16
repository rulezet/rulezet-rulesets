rule base64_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZnJlZSB1c2Vy"
    $a1="dXNlcg=="
    $a2="YWRtaW4="
    $a3="YWRtaW4="
    $a4="VXNlcg=="
    $a5="VXNlcg=="
    $a6="QWRtaW5pc3RyYXRvcg=="
    $a7="QWRtaW5pc3RyYXRvcg=="
    $a8="R3Vlc3Q="
    $a9="R3Vlc3Q="
    $a10="SVNfJGhvc3RuYW1l"
    $a11="SVNfJGhvc3RuYW1l"
    $a12="TERBUF9Bbm9ueW1vdXM="
    $a13="TGRhcFBhc3N3b3JkXzE="
    $a14="TVNIT01F"
    $a15="TVNIT01F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}