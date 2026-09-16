rule blake2b_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aefb7dbdda9ba4718c2cb6b0a795cdcbe8a2d77b3d58420e684c568815d03597f18d7012f5cbc356031d9eec0fb488c5da1a1ac6fcb50635c46202009dd1d229"
    $a1="aefb7dbdda9ba4718c2cb6b0a795cdcbe8a2d77b3d58420e684c568815d03597f18d7012f5cbc356031d9eec0fb488c5da1a1ac6fcb50635c46202009dd1d229"
condition:
    ($a0 and $a1)
}