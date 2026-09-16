rule sha3_256_hashed_default_creds_arun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for arun."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09d8409dfa0ba399cf95c6510b579542aba7b6230c6354dfb7090e9a9c0fe3d1"
    $a1="a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67"
condition:
    ($a0 and $a1)
}