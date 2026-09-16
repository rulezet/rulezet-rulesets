rule nthash_hashed_default_creds_postgres_postgres
{
    meta:
        id = "7fbHOfEbTXkVrbtJsdnR3p"
        fingerprint = "81fa7a0f3231373e7ffc4ea05dc7889cec0356e8aeef0bc2c959242575e6bb41"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="b9f917853e3dbf6e6831ecce60725930"
    $a5="78e72d03d0a633973c36503e82dd6566"
    $a6="3dbde697d71690a769204beb12283678"
    $a7="28278c7295f5487980d7238f1db3c12d"
    $a8="209c6174da490caeb422f3fa5a7ae634"
    $a9="28278c7295f5487980d7238f1db3c12d"
    $a10="f5f4e98a43c72439eda02844e6bf88f1"
    $a11="28278c7295f5487980d7238f1db3c12d"
    $a12="8846f7eaee8fb117ad06bdd830b7586c"
    $a13="28278c7295f5487980d7238f1db3c12d"
    $a14="28278c7295f5487980d7238f1db3c12d"
    $a15="28278c7295f5487980d7238f1db3c12d"
    $a16="bfaf153a310f8adff253a256f63ac35a"
    $a17="28278c7295f5487980d7238f1db3c12d"
    $a18="97364adee97317556a58e4fa4e834711"
    $a19="28278c7295f5487980d7238f1db3c12d"
    $a20="97364adee97317556a58e4fa4e834711"
    $a21="209c6174da490caeb422f3fa5a7ae634"
    $a22="9abbe71311e7615eb4509937f3a7bafb"
    $a23="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}