rule blake2s_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="af7934ee4422362eb36803d0174c8e3806ed6509fd4511474a8c7949fdaf0d41"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="f54118fba98154d2bcd55b64e65b4d2faf19da54581939a8ecfb35797f3ce3e8"
    $a3="6204076fc988d9c8ba327799ea12528be066aad0192027adfcd3b505067edd3e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}