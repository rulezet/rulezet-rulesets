rule mysql41_hashed_default_creds_samsung
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samsung."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6A70783D74C2C11A24E6BFC0AD68A1310597A982"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*A80082C9E4BB16D9C8E41B0D7EED46126DF4A46E"
    $a3="*A80082C9E4BB16D9C8E41B0D7EED46126DF4A46E"
    $a4="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*6F631A301F093CD22A4FDAF943401C3B349E6C08"
    $a7="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}