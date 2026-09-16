rule blake2s_hashed_default_creds_airaya_corp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for airaya_corp."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b21e098b84e8f4b386c2fadb236ccd2e6b289aabe3b0d802fd16362e249994ae"
    $a1="b21e098b84e8f4b386c2fadb236ccd2e6b289aabe3b0d802fd16362e249994ae"
condition:
    ($a0 and $a1)
}