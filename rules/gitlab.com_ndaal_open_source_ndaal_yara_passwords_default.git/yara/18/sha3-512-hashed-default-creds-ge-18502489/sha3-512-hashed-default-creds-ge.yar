rule sha3_512_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d28a3e47d736f7bc60a967d9c37b56c0fa00d823a5c7af0d1c3aa784bd7dfc79c728bf8ebffb5bfa16789900d7102428469e359cf907c35cbab75f14810c1e0"
    $a1="cd4b7fbc72046b18c433d03be47772154b1649702d0a9edb6870391166f7a7da66b6e83333a3969450c06cbf3ee2d3a2c95a5f5997603f906711e126457001b5"
condition:
    ($a0 and $a1)
}