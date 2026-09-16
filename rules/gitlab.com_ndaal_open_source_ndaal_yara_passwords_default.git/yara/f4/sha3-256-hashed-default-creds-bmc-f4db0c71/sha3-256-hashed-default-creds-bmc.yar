rule sha3_256_hashed_default_creds_bmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ce6299cea06e9502aa2c6e5dc13a38e224b346e973c4330f199266c895d35073"
    $a1="ce6299cea06e9502aa2c6e5dc13a38e224b346e973c4330f199266c895d35073"
condition:
    ($a0 and $a1)
}