rule blake2b_hashed_default_creds_topnet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topnet_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="131dccea634c42c5c371f024f112af7b9f687384ddfd6a7c48e995fae207f9eb4781d6b987df3ed481fd3cbffddf8c8e7d8f3095077cbfcba470083821014046"
    $a1="131dccea634c42c5c371f024f112af7b9f687384ddfd6a7c48e995fae207f9eb4781d6b987df3ed481fd3cbffddf8c8e7d8f3095077cbfcba470083821014046"
condition:
    ($a0 and $a1)
}