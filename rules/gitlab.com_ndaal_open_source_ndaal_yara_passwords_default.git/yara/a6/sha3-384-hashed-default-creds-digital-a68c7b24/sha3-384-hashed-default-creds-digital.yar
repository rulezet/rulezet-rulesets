rule sha3_384_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a15dfb85ab204b230943e24cb8aa2721cac311248d0327000762349f96cb0c55c1870d7fc15241756cb996d21e86d417"
    $a1="39773563a8fc5c19ba80f0dc0f57bf49ba0e804abe8e68a1ed067252c30ef499d54ab4eb4e8f4cfa2cfac6c83798997e"
condition:
    ($a0 and $a1)
}