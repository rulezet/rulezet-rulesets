rule base64_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c21j"
    $a1="c21jYWRtaW4="
    $a2="YWRtaW4="
    $a3="YmFycmljYWRl"
    $a4="YWRtaW4="
    $a5="c21jYWRtaW4="
    $a6="Y3VzYWRtaW4="
    $a7="aGlnaHNwZWVk"
    $a8="YWRtaW4="
    $a9="YWRtaW4="
    $a10="QWRtaW5pc3RyYXRvcg=="
    $a11="c21jYWRtaW4="
    $a12="bXNv"
    $a13="dzBya3BsYWMzcnVsM3M="
    $a14="QWRtaW4="
    $a15="QmFycmljYWRl"
    $a16="ZGVmYXVsdA=="
    $a17="V0xBTl9BUA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}