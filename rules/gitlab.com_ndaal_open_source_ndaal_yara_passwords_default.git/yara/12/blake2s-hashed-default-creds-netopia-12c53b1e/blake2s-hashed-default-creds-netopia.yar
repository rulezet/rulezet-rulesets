rule blake2s_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="51159e4877dd0c189bfccb3c8a4fa991fac8a766435d522d82f04d01341b7a7b"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="d1d90a972e12df922d9019c07d2ff7c767b8c1a5f0b7f4c7eafd9de4da954b9b"
    $a3="d1d90a972e12df922d9019c07d2ff7c767b8c1a5f0b7f4c7eafd9de4da954b9b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}