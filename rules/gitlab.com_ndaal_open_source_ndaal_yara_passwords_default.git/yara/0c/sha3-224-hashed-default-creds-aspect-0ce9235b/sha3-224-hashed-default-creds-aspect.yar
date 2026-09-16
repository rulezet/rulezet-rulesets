rule sha3_224_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="634c2f94abf7af46ed1bd91e0d9232c19a4377f841926e2a9593a641"
    $a1="c2fe3bf982847e3ddd1367530fbf855e8a9c43621783d172fd2ff2d2"
condition:
    ($a0 and $a1)
}