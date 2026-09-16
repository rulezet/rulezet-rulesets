rule sha3_224_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e82d2968d2b62a52a50c3a4becb4adcb8d4f0a5c6e5aee14a01a68ed"
    $a1="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a2="e82d2968d2b62a52a50c3a4becb4adcb8d4f0a5c6e5aee14a01a68ed"
    $a3="1f2b34adae97ba0be8aec562b00df7d82ba894326901788bc4ec25cf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}