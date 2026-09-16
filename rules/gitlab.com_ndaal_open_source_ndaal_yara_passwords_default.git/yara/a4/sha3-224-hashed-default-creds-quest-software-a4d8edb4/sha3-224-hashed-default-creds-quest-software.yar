rule sha3_224_hashed_default_creds_quest_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for quest_software."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2b92d529c5c32adaa80dd53668ead6642275cd1a6c390a64930a04f"
    $a1="c2b92d529c5c32adaa80dd53668ead6642275cd1a6c390a64930a04f"
condition:
    ($a0 and $a1)
}