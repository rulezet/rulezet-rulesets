rule mysql41_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a2="*635E70FC0BC3484295E6605F5AF0490732538A98"
    $a3="*432DADB80863E758A32913E510F74D01A605B00B"
    $a4="*37094A8E8BF520400ACE0F0679DEBE38C7143714"
    $a5="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a6="*24223885F235CAFE7FD4E78C2A79F4BD81EB3AC9"
    $a7="*432DADB80863E758A32913E510F74D01A605B00B"
    $a8="*9326E8C9853E62554E9C233FB1C9431E29540BCF"
    $a9="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a10="*45F2C3B4476FFF9AE3E6335C54339C17B96DB83B"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}