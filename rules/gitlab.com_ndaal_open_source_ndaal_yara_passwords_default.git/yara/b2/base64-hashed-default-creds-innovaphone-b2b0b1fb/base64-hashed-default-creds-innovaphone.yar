rule base64_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="aXAyMA=="
    $a2="YWRtaW4="
    $a3="aXAyMQ=="
    $a4="YWRtaW4="
    $a5="aXAzMDAw"
    $a6="YWRtaW4="
    $a7="aXAzMDVCZWhlZXI="
    $a8="YWRtaW4="
    $a9="aXA0MDA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}