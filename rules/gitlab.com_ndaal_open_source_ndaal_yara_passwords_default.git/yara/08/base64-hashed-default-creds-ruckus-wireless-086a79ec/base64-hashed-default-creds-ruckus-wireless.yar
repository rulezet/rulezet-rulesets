rule base64_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3VwZXI="
    $a1="c3AtYWRtaW4="
    $a2="YWRtaW4="
    $a3="cGFzc3dvcmQ="
    $a4="YWRtaW4="
    $a5="c3AtYWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}