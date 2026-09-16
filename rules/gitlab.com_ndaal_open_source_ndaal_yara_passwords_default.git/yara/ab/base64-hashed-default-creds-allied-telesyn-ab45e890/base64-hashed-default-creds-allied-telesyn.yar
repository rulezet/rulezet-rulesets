rule base64_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bWFuYWdlcg=="
    $a1="bWFuYWdlcg=="
    $a2="bWFuYWdlcg=="
    $a3="YWRtaW4="
    $a4="TWFuYWdlcg=="
    $a5="ZnJpZW5k"
    $a6="bWFuYWdlcg=="
    $a7="ZnJpZW5k"
    $a8="c2Vjb2Zm"
    $a9="c2Vjb2Zm"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}