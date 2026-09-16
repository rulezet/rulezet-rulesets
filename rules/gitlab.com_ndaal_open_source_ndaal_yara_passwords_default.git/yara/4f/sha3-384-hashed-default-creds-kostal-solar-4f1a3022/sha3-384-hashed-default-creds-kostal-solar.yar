rule sha3_384_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c27913abeb6bac2904419cb815b21086a5e76a1a27fea0f6e803bba840b323239c0c5cbe7b82d20410fa78f29f9486a7"
    $a1="da2dccd348608668aeaf9a1906b002e98bf9e39f6fa63ad9997ff5e5f47e669b48c65ef22ea93ddb0adee8308804a1f4"
condition:
    ($a0 and $a1)
}