rule sha3_512_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54bdd012232ff158c1a070e2b3c15748a1a3f6b647a671d88f7ed09cddbd68bf857ea39c3e29d29242b98d79cd9816434be10f4bc79d118917d1c8d5b800455d"
    $a1="f9f55f91fc6e1dfbb28c6e4712fe5e8eb6e74d039e0219da3bde556ade11fe12bac1c22b1e6d0c6dcf45d7f0d07d85af0c13bf54144e64636a112d4ffbdc8925"
condition:
    ($a0 and $a1)
}