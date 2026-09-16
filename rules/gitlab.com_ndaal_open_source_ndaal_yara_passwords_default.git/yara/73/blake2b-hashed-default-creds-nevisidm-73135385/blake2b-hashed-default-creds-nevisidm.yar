rule blake2b_hashed_default_creds_nevisidm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nevisidm."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ae29f94f9655f299dce9964c467e9f08addcdcde24b951dd00f454c138eae9217ba58f53e3a3d53adf4186f41dceb66aa71c6ceeb41b86db3a9c2c2d4217b87"
    $a1="48aad0545e3700894ed120eeea958eddc92f0fb8dfe7938fb109da50bdbe7b410f5dcae87751b5d99c0bd0dc4a03a069d8db23ca6af5d7672d97cd7a51e321f0"
condition:
    ($a0 and $a1)
}