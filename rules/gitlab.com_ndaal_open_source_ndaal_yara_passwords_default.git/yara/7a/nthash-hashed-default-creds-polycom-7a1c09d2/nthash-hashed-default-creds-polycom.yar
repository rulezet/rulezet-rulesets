rule nthash_hashed_default_creds_polycom
{
    meta:
        id = "10IZZUZTpuU0CJMdjjwIo7"
        fingerprint = "f37ed525cc1bbf45eebed6db4ed26b5545a226ee567be70b26912bebcaf9601f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a420e7750b39be09fa29d314fa4b51c"
    $a1="62cd12b827e5a98ffa3b4b2eac84b93c"
    $a2="893a0f7f1a11a5a0a0b6909e10c80f80"
    $a3="62cd12b827e5a98ffa3b4b2eac84b93c"
    $a4="75438937fa990c591097d354a3c056dc"
    $a5="a4141712f19e9dd5adf16919bb38a95c"
    $a6="47871e9502faab0aba6086ae35137fdc"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="778714772c8c129f00b4591f0755bb9f"
    $a9="62cd12b827e5a98ffa3b4b2eac84b93c"
    $a10="5a420e7750b39be09fa29d314fa4b51c"
    $a11="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}