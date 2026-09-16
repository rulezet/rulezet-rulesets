rule sha512_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="01e5ff205af9b5a1e197de2165ff8ae80f2d179b42556056e7adc8d3acebabea5a5864d5d8e7a9cd4e46f76604018cd653cc0eb21fb7998cdaa95b4387face9d"
    $a1="591409c4144947b130526b06577235a6162177196411470c3294e15d603aab6d642be1487c4a3ff91b6e068d6d9645cdc733131ad13b68b32ff9605103315a72"
condition:
    ($a0 and $a1)
}