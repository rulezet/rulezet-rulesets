rule sha3_224_hashed_default_creds_phpreactor
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="af727eb2ab5c39aaa570d1c506b3ba3baa72e9f99cb2433584a08e03"
    $a1="653f2b3fa3f9763ad936ede2df5a2e13e61349870c0a86ae8ca85f25"
condition:
    ($a0 and $a1)
}