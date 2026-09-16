rule sha3_224_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3bc5e50481c727313fa7a4aaf7fd28a4d9572d828a1345ba103d9df4"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="12db234edbcdc0820bb0fc91d05d2ddab42eae0386abc6ac77c45f05"
    $a3="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a4="44d674cbbca9652ee41799901d7c22526054a4a6e0e15d83747c89f6"
    $a5="03370c307219d3d33781c917e10df30471407b8097cf71487eb63c69"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}