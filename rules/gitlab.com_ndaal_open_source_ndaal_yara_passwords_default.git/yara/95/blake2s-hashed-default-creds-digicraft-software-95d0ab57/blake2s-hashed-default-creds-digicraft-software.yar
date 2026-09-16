rule blake2s_hashed_default_creds_digicraft_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicraft_software."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ab98a6e4ddfe395155a107b4474cc81c8ff27e334e8e2a8319290c938ecbdcf"
    $a1="1fb0f8f465816ecc563bfcdd9b241efefe9fd6d03adce135db7b13f2da9947f6"
condition:
    ($a0 and $a1)
}