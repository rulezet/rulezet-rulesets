rule sha3_224_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8fb01ff22b5cb74f8aa0f8beaddcabe9097ca4f33c42205221f9e37e"
    $a1="c7c9c1dc66925f4627f485e9e07cbf970d0e8ee704cef2a58b593956"
    $a2="8fb01ff22b5cb74f8aa0f8beaddcabe9097ca4f33c42205221f9e37e"
    $a3="18b2bd676ec9184b2c3d3f6e7e72bbb34f5d3aa035aa5b4bb1691029"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}