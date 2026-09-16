rule sha224_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ef0a48857e59814ce0ec978f684b4580eeae835e84ed01df137e377f"
    $a1="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a2="ef0a48857e59814ce0ec978f684b4580eeae835e84ed01df137e377f"
    $a3="8022ff7825f35bbeed2415087ac9899542a3ffe21a6084e16efe9bec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}