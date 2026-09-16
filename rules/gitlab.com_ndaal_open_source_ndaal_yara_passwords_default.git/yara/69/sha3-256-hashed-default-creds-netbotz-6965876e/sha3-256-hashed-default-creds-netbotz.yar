rule sha3_256_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6e83bc505c8e3191fe09eeb207e7343681e33dbf258cfa3e2257bd33c6e2c29"
    $a1="a6e83bc505c8e3191fe09eeb207e7343681e33dbf258cfa3e2257bd33c6e2c29"
condition:
    ($a0 and $a1)
}