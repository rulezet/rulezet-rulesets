rule blake2s_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a1="ae918098f371ebac3fc643a1c912f6dfb5ec408afa96202e010f756bf6540c37"
    $a2="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a3="26be7332a6591b0e6a6c4147b6e182efbf45eab6ad6b8e193fc521c0cc03ac6f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}