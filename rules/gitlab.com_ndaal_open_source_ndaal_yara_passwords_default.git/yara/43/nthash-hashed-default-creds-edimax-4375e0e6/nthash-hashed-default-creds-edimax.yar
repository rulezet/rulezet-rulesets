rule nthash_hashed_default_creds_edimax
{
    meta:
        id = "40OVj8u5lWlB1Vo0o4bAZK"
        fingerprint = "56d3085437fb1dfbc3bcb33b0af6bfde0a785d9544dc6c94bdbab22e69990b22"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="3dbde697d71690a769204beb12283678"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="4259f780246c8f93f5c66779eadba2c2"
    $a7="c78ec31a9431ec94c04c8caf2039463a"
    $a8="c130686c5e7390f6dfb455744d6ca639"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="9f68dc58b03c95d1f8f1d20448963856"
    $a11="209c6174da490caeb422f3fa5a7ae634"
    $a12="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a13="823893adfad2cda6e1a414f3ebdf58f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}