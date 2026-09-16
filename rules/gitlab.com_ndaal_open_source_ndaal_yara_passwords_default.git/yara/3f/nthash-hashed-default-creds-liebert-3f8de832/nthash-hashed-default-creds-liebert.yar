rule nthash_hashed_default_creds_liebert
{
    meta:
        id = "1ZJyDgoFH20mHHKTZPgcev"
        fingerprint = "fc9ebfad0b9b7ca6a1427916be0a20d620f2b4c45fb3402c812abe973447184d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bbc38d1937f4ad293ba6717fd4981e9b"
    $a1="bbc38d1937f4ad293ba6717fd4981e9b"
condition:
    ($a0 and $a1)
}