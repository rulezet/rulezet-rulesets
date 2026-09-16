rule nthash_hashed_default_creds_audiocodes_mediant_1000_web
{
    meta:
        id = "7GgX4ITB3FsFPbPZG8uVwB"
        fingerprint = "c7263a80a3ee4536296b50e03085d7ed02f33025423fdaeabfc8e5df7b2e278c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for audiocodes_mediant_1000_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a25b2710ba9de114396adc7dfb0a7235"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1)
}