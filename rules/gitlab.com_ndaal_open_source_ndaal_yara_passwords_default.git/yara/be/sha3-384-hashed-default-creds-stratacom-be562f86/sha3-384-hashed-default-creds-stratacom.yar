rule sha3_384_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="202310c64c6018f2d20bffca56af176e3f761f460a61239b979ffebbe0dddf625a1e0c0716b1acc5314738983dfe0e17"
    $a1="a36dc138cbce7b094201aa2e5b8b744d7042ac9e012df98a50c5e1c109d2ff4cbf8cc505b16ff5fa937ad17f13d164d7"
condition:
    ($a0 and $a1)
}