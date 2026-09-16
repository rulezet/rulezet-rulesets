rule nthash_hashed_default_creds_mysql
{
    meta:
        id = "6toY76jiNjbhfcx8ntlAPJ"
        fingerprint = "7c9da1212f6cc28086b27b7d70252419b5ef90e01b026baf9be2dced5d720ba7"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mysql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="8cd5419b4714f9c23733b2eb665b6205"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="8cd660715d326ad2e97daf80fc0a7019"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}