rule sha3_256_hashed_default_creds_fastwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fastwire."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="adc51ed9923c6a9318a8e56cbfea00b4786cbedf36fefdd12ce660dbc105e504"
    $a1="9cbf5ac0a9a96b60a95a9f33773a2ac5fc11bbcdb76cb1e96452161cf61ea66a"
condition:
    ($a0 and $a1)
}