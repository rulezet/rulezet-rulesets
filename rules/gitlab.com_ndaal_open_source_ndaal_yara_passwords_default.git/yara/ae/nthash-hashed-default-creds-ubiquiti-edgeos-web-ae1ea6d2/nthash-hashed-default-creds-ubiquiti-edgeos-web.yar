rule nthash_hashed_default_creds_ubiquiti_edgeos_web
{
    meta:
        id = "4BjbZbM871lGE4fPHquMmu"
        fingerprint = "d7c48c211b519d75c016229a6b9fdcbaa7930ad31ec1a41613150331344e9e23"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_edgeos_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db17d3fa744d127d0d5702eb1d913bb5"
    $a1="db17d3fa744d127d0d5702eb1d913bb5"
condition:
    ($a0 and $a1)
}