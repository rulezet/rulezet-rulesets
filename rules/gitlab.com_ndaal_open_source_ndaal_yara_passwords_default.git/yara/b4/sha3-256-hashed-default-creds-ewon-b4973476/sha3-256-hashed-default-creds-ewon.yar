rule sha3_256_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="184cd019129767f24837c19af5f50de7d9cd933566176f7a9bc5b15a76a309a9"
    $a1="184cd019129767f24837c19af5f50de7d9cd933566176f7a9bc5b15a76a309a9"
condition:
    ($a0 and $a1)
}