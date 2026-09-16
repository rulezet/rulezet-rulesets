rule base64_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="cmFyaXRhbg=="
    $a2="ZXBpcV9hcGk="
    $a3="cmFyaXRhbg=="
    $a4="d2ViX2FwaQ=="
    $a5="c2wzM3AzMEYwMGR1bWFzcyE="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}