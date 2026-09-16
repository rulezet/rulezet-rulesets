rule nthash_hashed_default_creds_schlage_sms_mssql
{
    meta:
        id = "2aRIy2U4YTimuEIoe2ZrRp"
        fingerprint = "a3c86a5263f206c891d93ba418e9fa20e4117756085eed87605c7baf6e79e63c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d22825a471801535dd101a8e803a4bb1"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
    $a2="d22825a471801535dd101a8e803a4bb1"
    $a3="6cd98bbeb78e2fe1bb3af336eff4a0da"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}