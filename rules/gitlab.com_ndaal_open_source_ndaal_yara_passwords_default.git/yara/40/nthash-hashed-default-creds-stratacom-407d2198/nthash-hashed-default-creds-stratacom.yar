rule nthash_hashed_default_creds_stratacom
{
    meta:
        id = "3ds2P4z7Y6iTipYJOl1utQ"
        fingerprint = "7231ae414edc2871f4ca48622c972301be2ccbe181712f30519c467480574e40"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fb1aaa778851d8459595ce00a412ee8"
    $a1="accf3448879525c02b72f9d983c9540e"
condition:
    ($a0 and $a1)
}