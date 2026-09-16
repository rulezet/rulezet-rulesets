rule sha3_512_hashed_default_creds_timeforce_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for timeforce_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a90f22ce6f8b1e57e09e497fda623a81c4375a538bf8750af1793fc022b9ebb5cffed3ca501c6d8ee684f5f98e5f29bd7cb573016a5f728ad3b4d069b04c981e"
    $a1="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a2="fb2851ba17f0069347a40687c0cddca50442ded8f25618527de7c76452558d474d4c42aff33fd2db3ef3f52e0dfe60059ef2e4edc32fde15cf7b46e2f36ef515"
    $a3="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}