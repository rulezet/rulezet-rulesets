rule sha3_224_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0ba629e1a8af632e9ff3f4fbc8b08b4fed373d45c212205070baa62f"
    $a1="4d3bd2f9b51c02b58bd735ce9668d87f7959bd1ed4d9cd068ecefce9"
condition:
    ($a0 and $a1)
}