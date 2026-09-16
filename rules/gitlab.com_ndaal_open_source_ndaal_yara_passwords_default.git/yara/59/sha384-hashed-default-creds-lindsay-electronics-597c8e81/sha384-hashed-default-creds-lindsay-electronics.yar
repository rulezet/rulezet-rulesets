rule sha384_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65372dc4d949dab3e02c263d711a7d953ef181c87959396a7d9dd541423e43e633377c45c7c00edab64cdc17aac01d64"
    $a1="eebd241a3d613fd87a4c30402fdd66b0667361380faafcfcb1bcc7e9c7029ca99137d974dd981b45ab947545bda0ec3d"
    $a2="65372dc4d949dab3e02c263d711a7d953ef181c87959396a7d9dd541423e43e633377c45c7c00edab64cdc17aac01d64"
    $a3="65372dc4d949dab3e02c263d711a7d953ef181c87959396a7d9dd541423e43e633377c45c7c00edab64cdc17aac01d64"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}