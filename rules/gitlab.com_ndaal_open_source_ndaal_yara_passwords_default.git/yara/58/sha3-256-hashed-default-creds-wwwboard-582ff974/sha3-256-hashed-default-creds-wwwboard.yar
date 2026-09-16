rule sha3_256_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90737781f2c8af2dec3909af0e73389e3e6bb43390641aa18d9766f1488261ef"
    $a1="765c936570c3b52588a1bb55b66384f51a938825183c15b21a3323581f301771"
condition:
    ($a0 and $a1)
}