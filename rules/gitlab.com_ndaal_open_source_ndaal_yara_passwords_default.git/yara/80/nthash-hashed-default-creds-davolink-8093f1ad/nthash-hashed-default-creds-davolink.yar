rule nthash_hashed_default_creds_davolink
{
    meta:
        id = "48S3oCvSjvLwBWsMOhS099"
        fingerprint = "cf919ee910ccb6ad26e14d1f6bb178814226171c1dc363c071a8a39017ce4d61"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for davolink."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="57d583aa46d571502aad4bb7aea09c70"
    $a1="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1)
}