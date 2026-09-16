rule nthash_hashed_default_creds_microcom
{
    meta:
        id = "4UQwhBlKxzyahknOAS0Pq5"
        fingerprint = "735b5dae123fb042b311c8cce22923d7c2106f0bfd34a06ee0495047b54eaed1"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microcom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f778814fcb55ba983ae40a80eeff52ad"
    $a1="f441f41aa59214cccc3d4ba5ed1550cc"
    $a2="c130686c5e7390f6dfb455744d6ca639"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="8f62e69c0919247c923b60a23c0e46b4"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="8846f7eaee8fb117ad06bdd830b7586c"
    $a7="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}