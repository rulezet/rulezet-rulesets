rule sha512_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b92d2ce65fc0503e90788f7ca2f8b2cb06a70971c3e13a6cc73c4b6d983760d482228135687a0c6d752d33ee398d2aa93cf70a030556ae6ad7ddeceb0d00ec69"
    $a1="ac9f96315639dc998ad7892e5849058d594ef535c5a57f530f27b20b6a571b5ead945e7b304abe4f922eec7d335cc068da702eb4273e3fc9efd8ac7446c1d90a"
condition:
    ($a0 and $a1)
}