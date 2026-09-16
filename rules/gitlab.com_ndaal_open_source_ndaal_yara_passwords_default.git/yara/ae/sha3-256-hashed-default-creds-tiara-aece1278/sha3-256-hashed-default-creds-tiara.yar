rule sha3_256_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65cb8399e1b0c707af3d3309028e39317742c1bb123c4257c1d9019f9da1ea00"
    $a1="bdb4ac0899250d3b1e82ead3c77ab3103870d1ad81d551a0c4c6a440c850abc0"
condition:
    ($a0 and $a1)
}