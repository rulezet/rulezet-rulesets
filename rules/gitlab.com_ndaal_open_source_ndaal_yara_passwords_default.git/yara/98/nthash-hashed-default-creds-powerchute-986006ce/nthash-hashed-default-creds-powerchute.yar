rule nthash_hashed_default_creds_powerchute
{
    meta:
        id = "3OmJcgcPH6Bg8XDHNuN3vx"
        fingerprint = "c219389ad2d560d9157f09bdc1df1ddaac4c8d587292d51be8c63c2fdace42ee"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b1a54b0f7c7dc6fff10b6c2f5fb9560"
    $a1="2b1a54b0f7c7dc6fff10b6c2f5fb9560"
condition:
    ($a0 and $a1)
}