rule sha3_384_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a97d23ce5dff1255f2c4d340f80508949b68f11a3e6840207d9d827fc617d15126adf06e366a123c4e32e5d090a95ca"
    $a1="c81746afb91c4f6e777e197e2534d80e345ea73820c148dd5b7ffc4c30482153e85c1850f7c93a15d21319edc7b7e03e"
condition:
    ($a0 and $a1)
}