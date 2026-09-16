rule sha3_384_hashed_default_creds_darkman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for darkman."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e804842b693589539e86f93ed38ba3dc4fd3dd113a9215ace8b9d1da1516abcfc59e10877a35dd44695d6d714360c4cf"
    $a1="e804842b693589539e86f93ed38ba3dc4fd3dd113a9215ace8b9d1da1516abcfc59e10877a35dd44695d6d714360c4cf"
condition:
    ($a0 and $a1)
}