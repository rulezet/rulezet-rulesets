rule sha256_hashed_default_creds_accelerated_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accelerated_networks."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc9fded673068945f828688898de3b94db0e41a733d939967ca3b29b4deb8970"
    $a1="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
condition:
    ($a0 and $a1)
}