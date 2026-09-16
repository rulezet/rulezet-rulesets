rule sha512_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36379d8584770820d95741c8efe571cc0ab37e2021c505fd8f384724d0676020ebc6d4f318e2533acf708fab8ede09c950a8daef54299ab9ea5ba1e1fd4b73bf"
    $a1="36379d8584770820d95741c8efe571cc0ab37e2021c505fd8f384724d0676020ebc6d4f318e2533acf708fab8ede09c950a8daef54299ab9ea5ba1e1fd4b73bf"
    $a2="b10bd422de7ed1bae87d0735dfeaf04e11ad2c30129a29083b6026ed1547b958004b5feced47ae7d411c1af1d4ae772e459315f5842d6ba3256f1cdaa76ac626"
    $a3="b10bd422de7ed1bae87d0735dfeaf04e11ad2c30129a29083b6026ed1547b958004b5feced47ae7d411c1af1d4ae772e459315f5842d6ba3256f1cdaa76ac626"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}