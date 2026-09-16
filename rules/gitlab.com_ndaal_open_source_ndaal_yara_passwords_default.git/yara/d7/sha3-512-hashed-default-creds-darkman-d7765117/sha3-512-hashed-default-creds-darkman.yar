rule sha3_512_hashed_default_creds_darkman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for darkman."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ffc1dcbe8c1ee16b60afa4522ea10b02392d3c9b394572f906e1ede44def4d6622c79b66f8e441eb016dc3c92bf4b112f4431943683ea3eca61ed5c92b68d33"
    $a1="8ffc1dcbe8c1ee16b60afa4522ea10b02392d3c9b394572f906e1ede44def4d6622c79b66f8e441eb016dc3c92bf4b112f4431943683ea3eca61ed5c92b68d33"
condition:
    ($a0 and $a1)
}