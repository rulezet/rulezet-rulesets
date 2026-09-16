rule base64_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bTExMjI="
    $a1="bTExMjI="
    $a2="dGVsZWNvbQ=="
    $a3="dGVsZWNvbQ=="
    $a4="Y2xpZW50"
    $a5="Y2xpZW50"
    $a6="bm9w"
    $a7="MTIzNDU="
    $a8="bm9w"
    $a9="MTIzNDU0"
    $a10="cm9vdA=="
    $a11="bm9raWE="
    $a12="cm9vdA=="
    $a13="cm9vdG1l"
    $a14="U2VjdXJpdHkgQ29kZQ=="
    $a15="MTIzNDU="
    $a16="VGVsZWNvbQ=="
    $a17="VGVsZWNvbQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}