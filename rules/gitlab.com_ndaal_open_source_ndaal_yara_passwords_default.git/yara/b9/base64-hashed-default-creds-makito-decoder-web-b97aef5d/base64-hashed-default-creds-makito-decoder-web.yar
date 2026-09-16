rule base64_hashed_default_creds_makito_decoder_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for makito_decoder_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="JTg5JUYwJTAxJThGJUQwJTAxJTgwJUYwJTAxJTg1JUQwJTAxJTgzJUYwJTAxJTgzJUUwJTAxJTg0JUYwJTAx"
condition:
    ($a0 and $a1)
}