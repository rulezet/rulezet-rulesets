rule nthash_hashed_default_creds_openconnect
{
    meta:
        id = "5JoZ6Okl6OFiJIX7wzIufe"
        fingerprint = "66c67c996b758a8c4f04e46bae11abadb01239d1981d23bdfa2e4f8cde114e37"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d0b21442b1db1c78c408c97ef3fe486"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="1d0b21442b1db1c78c408c97ef3fe486"
    $a3="f2381de8ded614bd9370cb447eff5f7e"
    $a4="1d0b21442b1db1c78c408c97ef3fe486"
    $a5="04e9548ba287f835fc085c34e2927c56"
    $a6="1d0b21442b1db1c78c408c97ef3fe486"
    $a7="d6bb75c90a14263244b31e2784354c2c"
    $a8="1d0b21442b1db1c78c408c97ef3fe486"
    $a9="aca699a0db2681748c775a062a0e29d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}