rule nthash_hashed_default_creds_dynalink
{
    meta:
        id = "5gsLFMga4ohR1xX8vjoGyb"
        fingerprint = "948e02b80f61df3f502bcc2a826d8876055cc9a889c30fc7aca20bcb0fb3b99d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dynalink."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="532a71d1afa4930012f3048d25f98148"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="cc31fcf26c6d03a16439ca1e8bfcf426"
    $a5="cd22e26f34cccbd15545721747a2e30c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}