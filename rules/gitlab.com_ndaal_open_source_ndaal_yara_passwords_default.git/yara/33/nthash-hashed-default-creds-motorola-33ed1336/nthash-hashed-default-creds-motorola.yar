rule nthash_hashed_default_creds_motorola
{
    meta:
        id = "U83ite2u63qdpfqA39o9P"
        fingerprint = "2b6ee599c15cd4c1f4ac953b7600b27b95f930ddc07feba5dd9fc420e0108a97"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd2351189d57d6cfde9e8f9cb96da06a"
    $a1="8d9be21fb0084317457f66e8ad649ba8"
    $a2="99aff69ed25ca5f45572c5503a10d28f"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="4ba57c94d500dd36627fde8fc037393b"
    $a7="f07206c3869bda5acd38a3d923a95d2a"
    $a8="b9caade7bf386df6ff023c57fb5e74fb"
    $a9="12150a212f41ef5a9cc0a17db93ea4c4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}