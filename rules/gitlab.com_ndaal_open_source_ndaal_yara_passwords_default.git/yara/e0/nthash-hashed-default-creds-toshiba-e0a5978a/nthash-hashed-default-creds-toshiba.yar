rule nthash_hashed_default_creds_toshiba
{
    meta:
        id = "7JoVVTHeJSq74PxJS7r7QX"
        fingerprint = "3054b90f71acf71830508e8e040f94c06c6f956583373dedc2b581ed4f3cd298"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="32ed87bdb5fdc5e9cba88547376818d4"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
    $a2="32ed87bdb5fdc5e9cba88547376818d4"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="160a5b7c7d1e2e685d9eee7f5509bdc5"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="76d202b312c8523d37fcdb4cd8288242"
    $a7="fad2607eda55ca3ecf8d89067ee91f84"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}