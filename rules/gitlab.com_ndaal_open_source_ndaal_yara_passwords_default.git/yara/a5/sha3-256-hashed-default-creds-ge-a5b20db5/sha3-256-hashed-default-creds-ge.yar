rule sha3_256_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4230a1aed6a63fb2400485a9dc979e5fa4ef641c1617c524e28c8ed92683c19a"
    $a1="1795d85b45233f701b8b0e97d2c9600e0ffb0b5e445bec0da3892d2d11b0e604"
condition:
    ($a0 and $a1)
}