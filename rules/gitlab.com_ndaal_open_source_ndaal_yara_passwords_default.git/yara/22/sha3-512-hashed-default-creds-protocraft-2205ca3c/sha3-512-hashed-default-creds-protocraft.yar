rule sha3_512_hashed_default_creds_protocraft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for protocraft."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e643c37f043f1f907ef0513a829ebc83892e5e06882a9a900be7a297087abae97581df5cae44b0510b8704ca2f5fb85746925446fc75790718a0de93858679c4"
    $a1="e5b987007670291ebcc757270fa96b43976e24441a7b385fb408b5d072a9a5179555d3fe602526f3340bbf13c7ed322e457e3c2fb73739cbdbcba51b4ab8c379"
condition:
    ($a0 and $a1)
}