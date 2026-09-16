rule md5_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d53d62056b878f168d5a560edd7b466b"
    $a1="d53d62056b878f168d5a560edd7b466b"
    $a2="92cc7568a3e07c4b82a166e9cabf7f1c"
    $a3="3a89c851a304f28577babc4252be6b4d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}