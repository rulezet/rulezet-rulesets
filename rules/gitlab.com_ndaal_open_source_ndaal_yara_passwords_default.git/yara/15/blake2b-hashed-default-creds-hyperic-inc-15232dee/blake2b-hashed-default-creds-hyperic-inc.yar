rule blake2b_hashed_default_creds_hyperic_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hyperic_inc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9a3dbb59c730596da4c896254ed275e3c9b2762d71d32b8a432451c4bdff585b9afa7a4cb395a09e5fe43029b7f5a9e6aa2411eb416ee102a4f5831e78e4724d"
    $a1="9a3dbb59c730596da4c896254ed275e3c9b2762d71d32b8a432451c4bdff585b9afa7a4cb395a09e5fe43029b7f5a9e6aa2411eb416ee102a4f5831e78e4724d"
condition:
    ($a0 and $a1)
}