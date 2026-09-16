rule nthash_hashed_default_creds_westell
{
    meta:
        id = "19wO6Z9lq28O9w1hYLOO3R"
        fingerprint = "a65d5a2a86f72114e22e37a790fa94b0263a1119513790ad2620ad9a09fb78e4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for westell."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5835048ce94ad0564e29a924a03510ef"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="236a85a6b2737671ced2a296fcf77eb1"
    $a3="75e9dacdfc0067f14b76077f8a27e15c"
    $a4="5f743046d4a6531434b826e035e4f21e"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="8846f7eaee8fb117ad06bdd830b7586c"
    $a7="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}