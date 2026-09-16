rule blake2s_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="06990a34eb39f5c651f666c0557808f94a4f646ab0343d78b0fd545a373dc185"
    $a1="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a2="06990a34eb39f5c651f666c0557808f94a4f646ab0343d78b0fd545a373dc185"
    $a3="388a104398d2efefac205ed6559d100d1135d882200e06e79a48c5196957c13f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}