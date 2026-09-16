rule nthash_hashed_default_creds_acti_web
{
    meta:
        id = "sfXhUXY6oK3l93WJ6GaYq"
        fingerprint = "7cb7cdbcfe2a077c59dd3e208d328738f1c1f3ec244631a22389324112beb5f8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a21990fcd3d759941e45c490f143d5f"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7a21990fcd3d759941e45c490f143d5f"
    $a3="a25b2710ba9de114396adc7dfb0a7235"
    $a4="32ed87bdb5fdc5e9cba88547376818d4"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="32ed87bdb5fdc5e9cba88547376818d4"
    $a7="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}