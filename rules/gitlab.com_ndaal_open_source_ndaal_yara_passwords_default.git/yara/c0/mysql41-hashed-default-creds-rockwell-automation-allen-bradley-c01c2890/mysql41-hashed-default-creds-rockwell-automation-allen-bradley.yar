rule mysql41_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a2="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*99ACC2D9A89606546A8AB1684F1EC3E89884DEFC"
    $a5="*A9340D88657188FF49AC10DFC0BF6FC8E8902638"
    $a6="*99ACC2D9A89606546A8AB1684F1EC3E89884DEFC"
    $a7="*FC726AED4F0E0A9196111E4958015337B9A44E7B"
    $a8="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a9="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a10="*F84CA0C34B072060E7FB01D9E00406D8269295A8"
    $a11="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a12="*14A3BF3DE2947AB353903EBDD15E283E13D8D8B3"
    $a13="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}