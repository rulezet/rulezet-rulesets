rule sha224_hashed_default_creds_informix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for informix."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a7364a1afedafc3c9ff5eacb8f003b23d2b4db4e82b4a3dea5ffb0a"
    $a1="4a7364a1afedafc3c9ff5eacb8f003b23d2b4db4e82b4a3dea5ffb0a"
condition:
    ($a0 and $a1)
}