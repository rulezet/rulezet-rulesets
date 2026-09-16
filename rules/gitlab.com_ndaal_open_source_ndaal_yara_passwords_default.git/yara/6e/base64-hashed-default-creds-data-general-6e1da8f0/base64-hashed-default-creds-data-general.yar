rule base64_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3BlcmF0b3I="
    $a1="b3BlcmF0b3I="
    $a2="b3A="
    $a3="b3A="
    $a4="b3A="
    $a5="b3BlcmF0b3I="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}