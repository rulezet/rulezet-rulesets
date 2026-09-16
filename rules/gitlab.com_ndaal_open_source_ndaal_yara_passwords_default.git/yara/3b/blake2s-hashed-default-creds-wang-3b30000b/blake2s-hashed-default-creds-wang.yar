rule blake2s_hashed_default_creds_wang
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wang."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ba65cc15cdeee558c99d048df19db19d1eaf48fc46743f294fb784a348a78622"
    $a1="96817c0b4b4fd3e1ef42dfd82426f21299ce3e10a4c2c5c55df3e2401b134bcd"
condition:
    ($a0 and $a1)
}