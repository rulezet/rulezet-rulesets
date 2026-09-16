rule mysql41_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*60D178145669A4D1569FE820852BB3425CB2D4A7"
    $a2="*1FDB0D828172183735F1ED9E45E6AF3CE04DE9D1"
    $a3="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a4="*89DE4724E0A55726B22671EEBF685D932B6FF9CB"
    $a5="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}