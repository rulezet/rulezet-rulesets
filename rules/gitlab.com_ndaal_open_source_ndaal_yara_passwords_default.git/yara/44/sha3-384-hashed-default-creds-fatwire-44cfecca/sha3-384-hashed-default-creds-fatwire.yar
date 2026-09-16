rule sha3_384_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6db1399f206bdb8d6d8b79dcfaaa508fbf2542ec462a6bfc964231961c5ec5faa92ebdc6fb5218544d26aa1ab97698ef"
    $a1="6db1399f206bdb8d6d8b79dcfaaa508fbf2542ec462a6bfc964231961c5ec5faa92ebdc6fb5218544d26aa1ab97698ef"
    $a2="5b750f48155c69d47ad10b987c2729c3723dfa3a68754f0f347c2dd29a87686fad21da1074f7edb6b0ccb519e206d4cf"
    $a3="d543d9ca0ed72c28f83c84fabe022a766d39e364e7c753c49473fc5aeb4c24daa190eec76f06ecb019b22b697f033eb5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}