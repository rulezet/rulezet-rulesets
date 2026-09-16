rule base64_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="eC1hZG1pbg=="
    $a2="YWRtaW4="
    $a3="MjIyMjI="
    $a4="YWRtaW4="
    $a5="YWRtaW4="
    $a6="YWRtaW4="
    $a7="MjIyMg=="
    $a8="MTExMTE="
    $a9="eC1hZG1pbg=="
    $a10="YWRtaW4="
    $a11="MTExMQ=="
    $a12="QWRtaW5pc3RyYXRvcg=="
    $a13="RmllcnkuMQ=="
    $a14="TlNB"
    $a15="bnNh"
    $a16="c2F2ZWxvZ3M="
    $a17="Y3Jhc2g="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}