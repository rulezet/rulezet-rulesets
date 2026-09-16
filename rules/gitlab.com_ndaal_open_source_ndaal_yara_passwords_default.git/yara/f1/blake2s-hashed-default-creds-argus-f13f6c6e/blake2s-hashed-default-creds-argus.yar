rule blake2s_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1afd6171483ae4dd7a2baf511850ebc9900b1adc9d8c37823a7a0650461a2c72"
    $a1="7bc949a244b64cf0831b70592c49d41bb3c5404b39576803da2840f8b4511c37"
    $a2="f018eaf04c595c3a82cc4ea20fabb1e49333d35a1430901244465165a57e85dc"
    $a3="f018eaf04c595c3a82cc4ea20fabb1e49333d35a1430901244465165a57e85dc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}