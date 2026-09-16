rule blake2s_hashed_default_creds_nevisidm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nevisidm."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ba42ac77ef8c2dc1630fd26b5f9bfa52cd26037649460f0b709bf5005949b3df"
    $a1="6e7dd38bc01f2dd5d18f898b77d6c59384bd32ea129d4b356120393aa76a81c2"
condition:
    ($a0 and $a1)
}