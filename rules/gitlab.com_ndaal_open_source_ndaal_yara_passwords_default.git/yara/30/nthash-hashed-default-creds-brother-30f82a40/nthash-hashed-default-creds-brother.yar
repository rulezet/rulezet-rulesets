rule nthash_hashed_default_creds_brother
{
    meta:
        id = "3SzF0dyEd4URvQCG65n3fn"
        fingerprint = "e3107cd0fe01e0676c4b189d9003dab752f2a4a122b597da9881d1ae03d03076"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brother."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e6342ecc5ed563057800830d710dd61"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="4e6342ecc5ed563057800830d710dd61"
    $a3="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}