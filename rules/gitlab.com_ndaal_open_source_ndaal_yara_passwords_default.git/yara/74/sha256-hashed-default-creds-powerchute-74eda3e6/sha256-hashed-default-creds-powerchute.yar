rule sha256_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97ff7d2d2520ef30b9c0d3c6b2101b69465b76ecc41db4534200e86ea5381831"
    $a1="97ff7d2d2520ef30b9c0d3c6b2101b69465b76ecc41db4534200e86ea5381831"
condition:
    ($a0 and $a1)
}