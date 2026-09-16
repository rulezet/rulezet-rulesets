rule sha3_384_hashed_default_creds_echelon_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon_corporation."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22b04b08a93d823f398886cd248706707270de24134156b7dcb73c39072a64d864a5f48555912542ad850e7724022ccc"
    $a1="22b04b08a93d823f398886cd248706707270de24134156b7dcb73c39072a64d864a5f48555912542ad850e7724022ccc"
condition:
    ($a0 and $a1)
}