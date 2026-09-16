rule sha3_256_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9cc39ccfa55cb57330a585fafd33191d6899deaab66b126f84401cdd34d18814"
    $a1="ebf929bc2bd69ce7f96d91d8ac79fb4f242428c625dc499abc1b6630891876e4"
    $a2="9cc39ccfa55cb57330a585fafd33191d6899deaab66b126f84401cdd34d18814"
    $a3="ce031053646935c8d6025cba26e47389c1adc495811b7632f3b092f666c49a50"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}