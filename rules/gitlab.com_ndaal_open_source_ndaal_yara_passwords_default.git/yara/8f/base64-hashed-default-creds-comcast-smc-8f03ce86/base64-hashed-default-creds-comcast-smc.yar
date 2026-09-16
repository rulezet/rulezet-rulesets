rule base64_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Y3VzYWRtaW4="
    $a1="Q2FudFRvdWNoVGhpcw=="
    $a2="Y3VzYWRtaW4="
    $a3="aGlnaHNwZWVk"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}