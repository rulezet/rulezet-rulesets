rule sha3_512_hashed_default_creds_blaeri
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for blaeri."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3aa8ac9ae6eaa5b7cb1f732874cebf934f04a76337e81a2452988b5ec67ad0cb5f4f1b32229d20a187bbbb0b44be7fa8bd2abc98860dfa8c33378c3a597e3860"
    $a1="59ddc1fbc4e29c4e57c7de1a7e8525a7e0d46fbaae4b4483668d7e37327adfc2d16910b87c42bd2f41a7c239365f6d60c16793c189c8fe6155e7886bee2c4723"
condition:
    ($a0 and $a1)
}