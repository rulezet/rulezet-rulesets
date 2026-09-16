rule sha3_384_hashed_default_creds_cellit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cellit."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1368a27f687cab00ae4d5de4d601110d1322b1345816a460d94f7ed68c2923c78fda34a0aeb1aa71184ca79f5813faf5"
    $a1="1368a27f687cab00ae4d5de4d601110d1322b1345816a460d94f7ed68c2923c78fda34a0aeb1aa71184ca79f5813faf5"
condition:
    ($a0 and $a1)
}