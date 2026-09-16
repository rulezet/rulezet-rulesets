rule blake2s_hashed_default_creds_meridian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for meridian."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cef0603e0ff8eb1842c0822f0fc3974b996589f8c15d8b82e95561054c29d159"
    $a1="b07dad53a0d27d81641f20c700df09617c238f16d36bfda78b5a57d71414f486"
condition:
    ($a0 and $a1)
}