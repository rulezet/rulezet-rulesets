rule sha384_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae958cc6b467f74d13d9b4223d48b7c22a513f85f1001c80ca5986040fe51d78662405653b08f0f53bbb39980a2840f3"
    $a1="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a2="ae958cc6b467f74d13d9b4223d48b7c22a513f85f1001c80ca5986040fe51d78662405653b08f0f53bbb39980a2840f3"
    $a3="9bc3a99dd6aa1babf302dcacff9eba070607e7f92c51efc9826697547a32297b24744525528e243597edbb5aa0c3f346"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}