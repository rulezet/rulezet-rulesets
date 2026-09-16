rule sha1_hashed_default_creds_adcon_telemetry
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcon_telemetry."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d4ca81abc2b9634c21c96a28e002745b62c7dddb"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}