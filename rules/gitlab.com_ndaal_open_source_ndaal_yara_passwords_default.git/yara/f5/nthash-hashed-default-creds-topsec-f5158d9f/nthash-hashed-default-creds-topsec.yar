rule nthash_hashed_default_creds_topsec
{
    meta:
        id = "6C5itZfBtMLVuMADySHnQT"
        fingerprint = "adf708a9f64d621eae89ded22aaae4cd34db440f1a15192c6d818858bcc5fee2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f372f5f7f0cdf604699e0154d1e3fadf"
    $a1="72f5cfa80f07819ccbcfb72feb9eb9b7"
condition:
    ($a0 and $a1)
}