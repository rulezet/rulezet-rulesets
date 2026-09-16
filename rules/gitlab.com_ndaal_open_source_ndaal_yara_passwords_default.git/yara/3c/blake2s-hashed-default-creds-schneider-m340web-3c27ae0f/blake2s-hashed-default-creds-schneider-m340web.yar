rule blake2s_hashed_default_creds_schneider_m340web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_m340web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8a1c8b86992301ad37a36d12d5e68f44e68912a17ebebfb62ca216c0d35a547"
    $a1="d8a1c8b86992301ad37a36d12d5e68f44e68912a17ebebfb62ca216c0d35a547"
condition:
    ($a0 and $a1)
}