rule nthash_hashed_default_creds_erpepe
{
    meta:
        id = "5flq9Oe8r1uOJNGFjCWyGH"
        fingerprint = "cc7c7d51ca78c47889c3b570c0d8e17f318da61345c66b0a4d8c99497787493f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ac258b08e5730574f882f45299d9c2c"
    $a1="c12a764b3d8da1ca60e7a5987c3b8592"
condition:
    ($a0 and $a1)
}