rule sha256_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6ef1856e376fff10d5159f5f6f5a8d35cb7032a3954c32a616ab9b91e7d19d3"
    $a1="e6ef1856e376fff10d5159f5f6f5a8d35cb7032a3954c32a616ab9b91e7d19d3"
condition:
    ($a0 and $a1)
}