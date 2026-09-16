rule sha3_224_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7e2c9df64e128b71efa615cfc7e79cfc66bd5ca6fae0414ce862de7"
    $a1="0a2c4b97e0dd6cee80df33d66d07f4146cb1a37e8c5c5ef25daf17cd"
    $a2="358e3c6529cda6548d2e592ad4716d219df5f6b712cb249ebf37e82b"
    $a3="b31e6c41b571759de5fb9d4b5a59653bbdcb345000ccf982be94ece5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}