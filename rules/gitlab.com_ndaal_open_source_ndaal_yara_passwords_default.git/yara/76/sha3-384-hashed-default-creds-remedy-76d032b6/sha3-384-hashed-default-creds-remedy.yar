rule sha3_384_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2dbc678d2b0ef9060ed75187c0f8262ac6111382096bd247571f75329d8c4da88aa75213d47794386ae2b4d0b64907ae"
    $a1="c41d308c572bc2aa6574a9fd8dc7fe268550ddeeb4e049b8508f6780198c13284f32b3a0cb1f91b44d6ab0eef22f4bce"
condition:
    ($a0 and $a1)
}