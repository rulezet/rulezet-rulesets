rule nthash_hashed_default_creds_johnson_controls
{
    meta:
        id = "5IEgiUktrzAHUdVtkpYQG8"
        fingerprint = "609e16a5da615d9feeb945c3c717e22b2e37acda29428f37956f06470fbd065d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for johnson_controls."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5dee007466506851d463d9941c70ec72"
    $a1="be16b10e3c3da6f36057807055024a3a"
condition:
    ($a0 and $a1)
}