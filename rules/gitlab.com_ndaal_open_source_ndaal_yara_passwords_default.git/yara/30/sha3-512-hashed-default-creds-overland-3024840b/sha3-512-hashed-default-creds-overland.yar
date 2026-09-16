rule sha3_512_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d887a0e79eb31a236584b5fbc521b86fb5fd317e9d5b381844d65da4e4f318bd354699208fd8f155f70e471e9a5048b815292fdc1f8b772d37410049a9cd1d89"
    $a1="6884d4025cc74257c32e357331c3c876da1609b7009d612d0da5197881e101efceaba542ea7fe1d216d3886a972723ad3cda8865585c29bba6711ceaa23a9525"
condition:
    ($a0 and $a1)
}