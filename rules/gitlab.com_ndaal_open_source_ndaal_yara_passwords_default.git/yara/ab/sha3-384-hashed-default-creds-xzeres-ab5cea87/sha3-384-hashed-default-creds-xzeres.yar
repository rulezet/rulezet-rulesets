rule sha3_384_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a819a40f4c31d74e30355c059eba6bc0cafdb2c2b8721dc1d37cde57d0a610db53c722a9ce37d0702cd19dfefad491e"
    $a1="0c8d5f70aae8cc9ec266e32b7160485adbec1f40c43b4957f143042bbf713738eae27f63629ace1b81b49f479bdb08fa"
condition:
    ($a0 and $a1)
}