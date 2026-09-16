rule blake2s_hashed_default_creds_tert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tert."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c3e17158535a9b5b4b4dbb0c4ffbd9085ec3513ff7d1cf8454ddad70d3a72e5"
    $a1="5c3e17158535a9b5b4b4dbb0c4ffbd9085ec3513ff7d1cf8454ddad70d3a72e5"
condition:
    ($a0 and $a1)
}