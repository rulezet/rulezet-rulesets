rule sha256_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="264de172cfe8b910cc5e8eef630ff78cac224101f14a01cd3661f66044691eaa"
    $a1="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a2="264de172cfe8b910cc5e8eef630ff78cac224101f14a01cd3661f66044691eaa"
    $a3="043e98d3441cf2d70e089418ca866efc8b14c496f71c3ee6eca3e6113dd17d2c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}