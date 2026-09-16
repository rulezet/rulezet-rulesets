rule sha3_224_hashed_default_creds_cellit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cellit."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4eb100e4c3113f2d961ec53cb83d77d1525391e3dbffc04810dc6463"
    $a1="4eb100e4c3113f2d961ec53cb83d77d1525391e3dbffc04810dc6463"
condition:
    ($a0 and $a1)
}