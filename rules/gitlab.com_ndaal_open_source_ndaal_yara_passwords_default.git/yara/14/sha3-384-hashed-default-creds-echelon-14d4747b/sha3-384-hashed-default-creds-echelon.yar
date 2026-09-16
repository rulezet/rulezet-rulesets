rule sha3_384_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22b04b08a93d823f398886cd248706707270de24134156b7dcb73c39072a64d864a5f48555912542ad850e7724022ccc"
    $a1="22b04b08a93d823f398886cd248706707270de24134156b7dcb73c39072a64d864a5f48555912542ad850e7724022ccc"
    $a2="3277048881406436896ad8ff320250609f161c8d03de6bb78d12e1a1602324100cbe1571d2e37c6786d2901c937901e9"
    $a3="6ca48b0a091f344d7ec10291910f4de7911c297591552047faf40c35c8cedc7848c6225e8032f0e0a6a4e86e70973c68"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}