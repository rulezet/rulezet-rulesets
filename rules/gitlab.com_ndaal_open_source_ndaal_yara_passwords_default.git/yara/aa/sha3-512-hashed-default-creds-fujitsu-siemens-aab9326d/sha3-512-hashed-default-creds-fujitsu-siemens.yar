rule sha3_512_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ea25d8aa99547f51d39d88f61528ad06f3d633d73adc03f5a5e4552a5fd4fd67a084644d4983b503632048c508f02909d6c0fd757e37431743a0a8a130452f74"
    $a1="9dde8fdbe67cea1d807f4185e8938ec259b2f1b1cfe45149f023476fcedb4badd97241109ef77130cc4048fed73129e3cf8404a728b2a41bcbc47be8215fa8a3"
condition:
    ($a0 and $a1)
}