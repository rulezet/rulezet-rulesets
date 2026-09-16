rule nthash_hashed_default_creds_allot
{
    meta:
        id = "5NwJvJaYhWtcN5ABVGlDyS"
        fingerprint = "9f65743763530db483aacbcff7eef4fda9327f5cafd150a8d792275e18a9918c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allot."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2c697c349a9dfb9d98b0d53fdb0be6b3"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="5c26dc8e9dd8a530025d0eb1d2b9d551"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}