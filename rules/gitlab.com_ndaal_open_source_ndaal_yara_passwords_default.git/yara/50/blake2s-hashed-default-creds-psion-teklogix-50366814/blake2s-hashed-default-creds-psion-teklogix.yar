rule blake2s_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7533ef9de3f659591de74e063c9cb128b8e9282589662a260aae4716824a5be"
    $a1="1b5d83df688dce6fb84623f2ae9af4472e4c0649d6d761f1351fcad784546dd0"
condition:
    ($a0 and $a1)
}