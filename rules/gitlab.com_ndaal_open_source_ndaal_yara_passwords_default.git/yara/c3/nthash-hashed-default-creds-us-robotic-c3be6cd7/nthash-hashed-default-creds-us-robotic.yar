rule nthash_hashed_default_creds_us_robotic
{
    meta:
        id = "10zXZHg7hec0pGXTRrwMgh"
        fingerprint = "7935a78d1eb214da980cdb5699cfcbb37722db7518a9bc0fa30c0a8ceccfff96"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotic."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e1dd34b128de1968a44212e05d9e942"
    $a1="1e1dd34b128de1968a44212e05d9e942"
condition:
    ($a0 and $a1)
}