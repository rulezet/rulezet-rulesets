rule blake2b_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d147bb827edf0b78c11b39f69d871a5025db05a5ccf97d86fd967842068ade17f4b84c3b0a7740216c077675e73b54784bf9f421d3213fedf2d470a10d8ba6f5"
    $a1="bc06ca99fc895f454b021a1413c304f0b81f0b0a53285cc185f23d2eef4d6b31cf50b64fe8eceac3c5cfe729b7b1d1f0e6eef0ee08cff30788317adada1362f0"
condition:
    ($a0 and $a1)
}