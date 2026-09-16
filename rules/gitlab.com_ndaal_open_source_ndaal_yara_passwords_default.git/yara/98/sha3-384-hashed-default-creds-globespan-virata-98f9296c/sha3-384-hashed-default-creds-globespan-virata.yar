rule sha3_384_hashed_default_creds_globespan_virata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for globespan_virata."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="958810aed7c6dff7c26e425a9b2a346ea6fbd3dee4d7ebaf7642b959020ee1004d17d5a55a21c8ab392b3c5af97056f5"
    $a1="958810aed7c6dff7c26e425a9b2a346ea6fbd3dee4d7ebaf7642b959020ee1004d17d5a55a21c8ab392b3c5af97056f5"
condition:
    ($a0 and $a1)
}