rule blake2s_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b07dad53a0d27d81641f20c700df09617c238f16d36bfda78b5a57d71414f486"
    $a1="b07dad53a0d27d81641f20c700df09617c238f16d36bfda78b5a57d71414f486"
    $a2="ecd5afadbdf81199e9e4d53396291eaf6b0af0ddf8b5b89546e101bd32a13c26"
    $a3="ecd5afadbdf81199e9e4d53396291eaf6b0af0ddf8b5b89546e101bd32a13c26"
    $a4="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a5="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}