rule sha384_hashed_default_creds_garrettcom_magnum_switchweb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for garrettcom_magnum_switchweb."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a1="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
condition:
    ($a0 and $a1)
}