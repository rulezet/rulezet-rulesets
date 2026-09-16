rule sha3_384_hashed_default_creds_johnson_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for johnson_controls."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f826e80c0522c109724f73d0ef8856721045b61bb47f08c01a03cfd313517b4f67cbcc8ace91fe414e99bec5b7cddf48"
    $a1="dfbe9d0c6a889ad4c9b8e7c8fad1fe8e4d8d5e162f464c7b06d2ec4cd50774146ceac15015a03d5280fdf53a78c08992"
condition:
    ($a0 and $a1)
}