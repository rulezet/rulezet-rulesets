rule sha3_384_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36dcaaced3983ec40e6e96dff0a2727094f20d7b86c3fcc77d36999d2fb11578a7bf81a34f57997e0ebc04fc55dfb468"
    $a1="99d30ebf55582c8702df271b343564eee72cf6b63845c345dd3c14eea232a38dfa18c914b817a800d18ea41621b2350c"
condition:
    ($a0 and $a1)
}