rule sha3_256_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ce34707fa4039f51d576c654abdc0eeb01450307fcf238eed7a45251c3e75d31"
    $a1="d602706f945af50ba5b0a4669ab4bdcd11f65dcca072e8cad2bd64367c88c7bc"
condition:
    ($a0 and $a1)
}