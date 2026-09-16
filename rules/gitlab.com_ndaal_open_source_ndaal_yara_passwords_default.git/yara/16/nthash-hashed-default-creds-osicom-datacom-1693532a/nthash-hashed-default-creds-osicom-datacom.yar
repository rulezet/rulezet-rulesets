rule nthash_hashed_default_creds_osicom_datacom
{
    meta:
        id = "22BogiTGaHqnRtTBWKHYbR"
        fingerprint = "a62ee105a20c36d2e19b1bdc190c3c1c2df31ef905b294e0f31fee1fa9c2e3c0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom_datacom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94aa68f72ab39cfec7ffcb58dca3358c"
    $a1="94aa68f72ab39cfec7ffcb58dca3358c"
condition:
    ($a0 and $a1)
}