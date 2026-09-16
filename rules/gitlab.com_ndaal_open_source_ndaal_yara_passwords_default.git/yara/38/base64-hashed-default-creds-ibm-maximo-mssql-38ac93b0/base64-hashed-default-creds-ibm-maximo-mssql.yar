rule base64_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bWF4YWRtaW4="
    $a1="bWF4YWRtaW4="
    $a2="bWF4cmVn"
    $a3="bWF4cmVn"
    $a4="bXhpbnRhZG0="
    $a5="bXhpbnRhZG0="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}