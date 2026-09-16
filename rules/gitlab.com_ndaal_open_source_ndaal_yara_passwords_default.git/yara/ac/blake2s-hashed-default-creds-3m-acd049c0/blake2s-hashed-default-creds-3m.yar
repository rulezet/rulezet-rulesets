rule blake2s_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90401a1ec1d23d8b1979ee0a1f632186781fdb749ea3f431d3c1bebbbdce7a21"
    $a1="90401a1ec1d23d8b1979ee0a1f632186781fdb749ea3f431d3c1bebbbdce7a21"
condition:
    ($a0 and $a1)
}