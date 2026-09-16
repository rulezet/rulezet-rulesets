rule sha3_384_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e04974694f81a0c7e245ecfe35f884290885a9c381959d2d7bff65aa966ca72c710f4c576304780e0adcdf07b11be25d"
    $a1="e04974694f81a0c7e245ecfe35f884290885a9c381959d2d7bff65aa966ca72c710f4c576304780e0adcdf07b11be25d"
    $a2="20d2b5f96d6b4a68307208046c6ba957b40d108f12e14e30e0f033bfc7a6f2ea377e08b44936450ee83eeb9eed0cae9e"
    $a3="03f4c36b38d0ce500a2418b15a6790b31ad794b690601cdbab1776f6d891bcd74ab72002be12098270c879d8e858a88f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}