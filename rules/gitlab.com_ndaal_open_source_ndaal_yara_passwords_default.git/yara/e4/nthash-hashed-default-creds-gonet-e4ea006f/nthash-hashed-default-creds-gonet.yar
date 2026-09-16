rule nthash_hashed_default_creds_gonet
{
    meta:
        id = "2WvvwMkPpsBt911CBTHesi"
        fingerprint = "d005ca495c92865c754640a9b5ac602446a8f112e3b854ca882a06cd08a886d2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a957d84dd117cc939f22ff7fa4a6faac"
    $a1="4b8bb0dcada9b1b46885b4814984b4b9"
condition:
    ($a0 and $a1)
}