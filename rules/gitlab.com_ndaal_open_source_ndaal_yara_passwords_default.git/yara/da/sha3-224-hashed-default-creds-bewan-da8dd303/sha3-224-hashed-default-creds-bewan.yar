rule sha3_224_hashed_default_creds_bewan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bewan."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="719b167a6a26866d90b5031350e77e0d90c1cf15e1b7563c09a68423"
    $a1="719b167a6a26866d90b5031350e77e0d90c1cf15e1b7563c09a68423"
condition:
    ($a0 and $a1)
}