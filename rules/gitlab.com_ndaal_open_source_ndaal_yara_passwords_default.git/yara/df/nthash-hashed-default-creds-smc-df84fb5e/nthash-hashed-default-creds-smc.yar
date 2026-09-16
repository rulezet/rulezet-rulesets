rule nthash_hashed_default_creds_smc
{
    meta:
        id = "1wMqjW22HhiuWS4d3ezECu"
        fingerprint = "190196ac9133e17651a65432b6f315110861f9b7534baaa04858e8f7e1f067b8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6febcbb8580e37608c064d30d172c34"
    $a1="15d7564478f326d273fe61e638502a2b"
    $a2="ddf8302fceeb363186d9aea153b941b0"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="c6febcbb8580e37608c064d30d172c34"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="1365f3c68d81a3a228b27e4e4031c84b"
    $a7="6c5ec0cf3aa0cfb9b96139eac847b13f"
    $a8="209c6174da490caeb422f3fa5a7ae634"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="c6febcbb8580e37608c064d30d172c34"
    $a11="d144986c6122b1b1654ba39932465528"
    $a12="bd110912eb662082d5ec523012665631"
    $a13="d06f57db3352437dc24b89e528a5c3dc"
    $a14="ac52736ba2b458e075e0228ec1bc855f"
    $a15="a25b2710ba9de114396adc7dfb0a7235"
    $a16="2cc4709c395e1fa3c40b2c03c79ea9bd"
    $a17="7d891ab402caf2e89ccdd33ed54333ac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}