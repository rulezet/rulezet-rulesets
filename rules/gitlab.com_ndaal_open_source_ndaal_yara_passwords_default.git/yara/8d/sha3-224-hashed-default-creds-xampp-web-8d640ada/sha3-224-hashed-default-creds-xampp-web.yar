rule sha3_224_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1bbb9ea5ac4b0b8c102e781161d390759da92e703831994bea7a3712"
    $a1="aac83e77887d2403c910147f28c143b4ca55ca9b309106e2ddb43b0b"
condition:
    ($a0 and $a1)
}