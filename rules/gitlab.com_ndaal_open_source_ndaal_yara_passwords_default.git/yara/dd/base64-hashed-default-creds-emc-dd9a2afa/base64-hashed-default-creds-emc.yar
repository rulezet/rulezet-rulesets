rule base64_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="Y2hhbmdlbWU="
    $a2="YmFja3Vwb25seQ=="
    $a3="YmFja3Vwb25seTE="
    $a4="YmFja3VwcmVzdG9yZQ=="
    $a5="YmFja3VwcmVzdG9yZTE="
    $a6="ZHBu"
    $a7="Y2hhbmdlbWU="
    $a8="TUNVc2Vy"
    $a9="TUNVc2VyMQ=="
    $a10="cmVzdG9yZW9ubHk="
    $a11="cmVzdG9yZW9ubHkx"
    $a12="cm9vdA=="
    $a13="OFJ0dG9Ucml6"
    $a14="cm9vdA=="
    $a15="Y2hhbmdlbWU="
    $a16="dmlld3VzZXI="
    $a17="dmlld3VzZXIx"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}