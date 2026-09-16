rule sha3_224_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d263b1a42751fec04f7d158f17d618e58e278ecf7ada3dc66c3e097c"
    $a1="d263b1a42751fec04f7d158f17d618e58e278ecf7ada3dc66c3e097c"
condition:
    ($a0 and $a1)
}