rule sha3_224_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3a27b6cfed60dc0b7b38b91d4117cda589846446ea030c76bea3d9be"
    $a1="88312723ae99a77f58d0351d6e35f949af12307d075abc6e399cf2dd"
    $a2="b2b35702e8b6ba1e25a2a925085ed36b4bfdf0c48e017ebefcc9af7b"
    $a3="b2b35702e8b6ba1e25a2a925085ed36b4bfdf0c48e017ebefcc9af7b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}