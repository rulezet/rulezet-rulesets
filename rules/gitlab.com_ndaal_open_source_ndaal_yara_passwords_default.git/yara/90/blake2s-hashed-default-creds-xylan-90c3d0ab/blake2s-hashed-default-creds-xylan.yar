rule blake2s_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="2c96f501eb50f9bd0a37146a68964daf02a4daa903fa7e390cfe84c07446dc80"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="2c96f501eb50f9bd0a37146a68964daf02a4daa903fa7e390cfe84c07446dc80"
    $a5="3ce461e8f901e67371da46cfaee864e3f56e47ff4ae205cc502ce19a8b8ff9c1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}