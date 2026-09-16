rule sha3_256_hashed_default_creds_globespan_virata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for globespan_virata."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ce0dfdb152de7fdf187917d88b8f1530f6820b594d47a3d3e28100ed9d94db6b"
    $a1="ce0dfdb152de7fdf187917d88b8f1530f6820b594d47a3d3e28100ed9d94db6b"
condition:
    ($a0 and $a1)
}