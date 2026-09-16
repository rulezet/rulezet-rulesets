rule nthash_hashed_default_creds_hirschmann
{
    meta:
        id = "5BRh1xSzxpscPAmLLEFBnB"
        fingerprint = "a8df1db71803b879e25fb51455d99be3f8a1bf73df6a7cfc31327f0c91766cb7"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hirschmann."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db51013b2730e1f16df6db7c3a73ad60"
    $a1="57d583aa46d571502aad4bb7aea09c70"
    $a2="532a71d1afa4930012f3048d25f98148"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}