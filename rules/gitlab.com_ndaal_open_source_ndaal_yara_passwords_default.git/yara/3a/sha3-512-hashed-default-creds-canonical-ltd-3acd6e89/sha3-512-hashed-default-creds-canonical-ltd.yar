rule sha3_512_hashed_default_creds_canonical_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canonical_ltd."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22a5268c060821b8f4a055833d2f3dbc67322f13b032a57bf0cfe5d3fad1c5838cac598ed3d7a67ecc696bbef8d868c80b2a223af8096255f1790d29ea922103"
    $a1="22a5268c060821b8f4a055833d2f3dbc67322f13b032a57bf0cfe5d3fad1c5838cac598ed3d7a67ecc696bbef8d868c80b2a223af8096255f1790d29ea922103"
condition:
    ($a0 and $a1)
}