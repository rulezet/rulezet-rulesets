rule nthash_hashed_default_creds_silicon_graphics
{
    meta:
        id = "18dkPAxIIeAKUdBLNIb5XV"
        fingerprint = "d455a138fe2cad1f91e4e095555312dfcea7b992bae3ab46a9bc164e1d890162"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="77e918b2be14ef27f80fc5151ca73e54"
    $a1="77e918b2be14ef27f80fc5151ca73e54"
    $a2="c3a23eb3f9e371403d51ab7a5810d2c1"
    $a3="c3a23eb3f9e371403d51ab7a5810d2c1"
    $a4="2ccf1f9609a7c6739112e14f760d565a"
    $a5="2ccf1f9609a7c6739112e14f760d565a"
    $a6="e5b4cf7b85c2e8f8027b5395ef7de843"
    $a7="e5b4cf7b85c2e8f8027b5395ef7de843"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}