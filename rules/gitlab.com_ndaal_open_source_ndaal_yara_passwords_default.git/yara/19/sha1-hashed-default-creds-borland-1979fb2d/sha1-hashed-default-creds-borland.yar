rule sha1_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3179a65eff2523bbde53c99b299b719c10a35235"
    $a1="4e3e05259ab29b6c37e983a73c99bf874da2cd9a"
    $a2="3179a65eff2523bbde53c99b299b719c10a35235"
    $a3="06a14ed1c9189015f75dd79606334dea9650a116"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}