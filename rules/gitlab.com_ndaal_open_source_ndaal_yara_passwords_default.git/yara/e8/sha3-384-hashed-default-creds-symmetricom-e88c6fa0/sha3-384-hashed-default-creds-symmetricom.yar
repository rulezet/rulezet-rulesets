rule sha3_384_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b141a7528b9be8a1e2ba370c63318a8da679e4ca52794c08b54af816887b63fd00d0df6dd1054b52e292b9a239b320c8"
    $a1="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a2="87441edcac54daef0d79c2cc489734e5a25d3d58e104245e6393a1b63921618ac611b844ec2f81236af8b6e06bc5996f"
    $a3="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}