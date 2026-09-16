rule sha3_256_hashed_default_creds_apc_ups_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_ups_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a1="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
condition:
    ($a0 and $a1)
}