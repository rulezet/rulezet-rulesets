rule nthash_hashed_default_creds_xerox
{
    meta:
        id = "5BuowgjRbo5ufXFur9EMo2"
        fingerprint = "47620bbe90640058335279b00bebb35bf8e0ffb6cd31c6fd0e196fbb18455b47"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fefe07fb9c1ab627d9545a8f911b87da"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="76178e956fc1907df6d1eb623675f1d5"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="209c6174da490caeb422f3fa5a7ae634"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="e0b6de1a35921a09e3b75fc198d5b5e8"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="fefe07fb9c1ab627d9545a8f911b87da"
    $a9="e9fceff7358f2d3bbac2b31841e874f2"
    $a10="e84d037613721532e6b6d84d215854b6"
    $a11="209c6174da490caeb422f3fa5a7ae634"
    $a12="443af5b862b902ba97b6def62d1a5830"
    $a13="d144986c6122b1b1654ba39932465528"
    $a14="80da48545ac26a0770181bc8ab157847"
    $a15="2c9c743c52af1da6715934f65100e7d6"
    $a16="af120e1553d7b5b5bc64d65df627cfe8"
    $a17="99ee32461192994ff6e77a49b6dc36f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}