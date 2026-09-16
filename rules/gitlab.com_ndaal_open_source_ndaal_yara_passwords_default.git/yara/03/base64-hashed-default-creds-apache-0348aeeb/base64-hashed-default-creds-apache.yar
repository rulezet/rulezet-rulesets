rule base64_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="ajVCcm45"
    $a2="YWRtaW4="
    $a3="YWRtaW4="
    $a4="YWRtaW4="
    $a5="dG9tY2F0"
    $a6="cm9sZQ=="
    $a7="Y2hhbmdldGhpcw=="
    $a8="cm9sZTE="
    $a9="cm9sZTE="
    $a10="cm9vdA=="
    $a11="Y2hhbmdldGhpcw=="
    $a12="cm9vdA=="
    $a13="cm9vdA=="
    $a14="dG9tY2F0"
    $a15="Y2hhbmdldGhpcw=="
    $a16="dG9tY2F0"
    $a17="dG9tY2F0"
    $a18="Ym90aA=="
    $a19="dG9tY2F0"
    $a20="cm9sZTE="
    $a21="dG9tY2F0"
    $a22="YWRtaW4="
    $a23="amJvc3M0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}