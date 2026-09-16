rule blake2b_hashed_default_creds_pikatel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pikatel."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7048ee929f2ea8d4c3e02bbd872bad3d1ceb51fd4b2e9566d0b8c180a493c91b30a1d5fb9088c1153084217d27e6bc615079efe6147c53fff94a672765a57da"
    $a1="f7048ee929f2ea8d4c3e02bbd872bad3d1ceb51fd4b2e9566d0b8c180a493c91b30a1d5fb9088c1153084217d27e6bc615079efe6147c53fff94a672765a57da"
condition:
    ($a0 and $a1)
}