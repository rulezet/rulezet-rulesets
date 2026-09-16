rule sha224_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b79ccc933306b4be7d2f499aa20fcc2e63820217e1a5f0d4d7476977"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="afb7120ab71a720f35ab638bec3968c12dd012a2cb52f4809ca607e0"
    $a3="4ce554b51c95da14f962dd11ead04c4c649ceaf50f059b58f8879a44"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}