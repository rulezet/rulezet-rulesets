rule blake2s_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fa108f7c1494550c600e2f174bce4371173840e5376c20e0cd127372806c46e"
    $a1="fa0c39a1d1860925ea0e571a3a74e81d041d322ff8e8aceb420fd52e756365c9"
condition:
    ($a0 and $a1)
}