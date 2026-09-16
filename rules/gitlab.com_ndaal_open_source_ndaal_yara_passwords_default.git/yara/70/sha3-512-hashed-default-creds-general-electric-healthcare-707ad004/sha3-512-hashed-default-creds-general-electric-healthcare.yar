rule sha3_512_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a2="dad451059568dccfe73b5e8f8575b0e4e283b9c4559e9fda90a729fa7843fcd242ca725729b9e6cdc0f6d9d3787793a1ea4b05b7d485e224f90e36b56d1364bd"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="dad451059568dccfe73b5e8f8575b0e4e283b9c4559e9fda90a729fa7843fcd242ca725729b9e6cdc0f6d9d3787793a1ea4b05b7d485e224f90e36b56d1364bd"
    $a5="dad451059568dccfe73b5e8f8575b0e4e283b9c4559e9fda90a729fa7843fcd242ca725729b9e6cdc0f6d9d3787793a1ea4b05b7d485e224f90e36b56d1364bd"
    $a6="30c2a0029c6fd4b4c451efc99a2534f60468427cd0167cc6c6d302832c2a3aa399f8fa33952f6f5bb855d2cfb5714226c397514b7bb75fae1763bb97176bc1af"
    $a7="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a8="aee3be29a8f6de2700e34a3dc62554cae59d4b5715749f38757d7a4b8b7579e934e042d2fe2b9695859262cba51cf6bb1fc8ba315b3909179dfe3aeb09648ae7"
    $a9="cbd3b2afcee3515c7dbbfa33108247acca8c00e82f072f536f270eb594a18e3aa60637d1a883205262b96783f9ce3b00c7a70ec8b8c6f78340651de2bfc5d23a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}