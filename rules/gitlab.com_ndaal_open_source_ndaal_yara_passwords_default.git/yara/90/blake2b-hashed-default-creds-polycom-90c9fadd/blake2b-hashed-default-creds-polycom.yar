rule blake2b_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98186e8212d82bfdcf950da3075d0bf7caaf55e9f52155beb6c9230559d2970a90f11ba4c4b486a2cafbb51f3c8fbe9bd4b386eb13ad03dcc974c22a30bdfd05"
    $a1="6262dce6abf2bb4ec25766c1c025db1d4b714cca01413c3e494d52393baf14de0c0cb19ac191e288e588e4fad9b34383c8caeee8311d085734fb3c230d33304a"
    $a2="e0c680e19cc0d6a3661209a56431c23d0144f1add2d9f815e6065ac1b54ff56822fe2af3b649f1fdcb631977466497abac925deb21b09aca0bdd321f68bd6d41"
    $a3="6262dce6abf2bb4ec25766c1c025db1d4b714cca01413c3e494d52393baf14de0c0cb19ac191e288e588e4fad9b34383c8caeee8311d085734fb3c230d33304a"
    $a4="f1020c2452a3847b7c9a82a054800c7a26e6d79ef9c380d9b3d5f0b2f47aac3a0d2bd7c2ed4d19677de9c25bdf25329078420cf12ae3f1656d76c7c4cf9f5a2c"
    $a5="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a6="87498478322b2dd634b587e2b88688fbbfaa412d26177d0708cd1190101320abc21025baa14aaee3640bc073cca1b83bb0a4bf0c9d6409c31e85a5feb7cc9662"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a8="a20657473838a54d50b5b6ffd6610d84dd8389b988723ffdd516e6f5472cbb4705b90abb5be970bc061f2bb89048de00b1978681967de86a1c7c612c7762362d"
    $a9="6262dce6abf2bb4ec25766c1c025db1d4b714cca01413c3e494d52393baf14de0c0cb19ac191e288e588e4fad9b34383c8caeee8311d085734fb3c230d33304a"
    $a10="98186e8212d82bfdcf950da3075d0bf7caaf55e9f52155beb6c9230559d2970a90f11ba4c4b486a2cafbb51f3c8fbe9bd4b386eb13ad03dcc974c22a30bdfd05"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}