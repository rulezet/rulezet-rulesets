rule nthash_hashed_default_creds_jamf_software
{
    meta:
        id = "6jCMMFbP37R7iSXcfs4Ke8"
        fingerprint = "528f13dbcf7c011417eb40cb70ac5f53d5dc0f24ae36a55f1b746760cf9cd9ec"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7be8c485b3eed3a0ed82c1a8bbb9725"
    $a1="a446a079e227e510f8cadac13eaee18a"
condition:
    ($a0 and $a1)
}