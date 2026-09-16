rule blake2s_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6dd76f938dabc37748c5934da402d450a3344e7ad93f3fe02dc98af57750c15"
    $a1="6204076fc988d9c8ba327799ea12528be066aad0192027adfcd3b505067edd3e"
    $a2="e6dd76f938dabc37748c5934da402d450a3344e7ad93f3fe02dc98af57750c15"
    $a3="10181969db5f4cef12345d13bff7fe535e47cc11e54b634be963e760f36aa021"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}