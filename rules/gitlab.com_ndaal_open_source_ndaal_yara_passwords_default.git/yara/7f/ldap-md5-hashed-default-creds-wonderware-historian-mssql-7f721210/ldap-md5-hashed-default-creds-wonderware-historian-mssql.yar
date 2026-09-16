rule ldap_md5_hashed_default_creds_wonderware_historian_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware_historian_mssql."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}R++hSLPyQorgcuKmbHeeUw=="
    $a1="{MD5}nPKQOqxr9foodF637OecDw=="
    $a2="{MD5}sQXnIl/KQE5UK+WBGhKOVQ=="
    $a3="{MD5}A4MV/4QGuS1Kya9D8cw/7A=="
    $a4="{MD5}ofwLTcTrEdG4//60ibYVfA=="
    $a5="{MD5}Rga0rUSzopqTjKS65Xq+CA=="
    $a6="{MD5}6G8ZJDZtXi2b7efpdYR2Cw=="
    $a7="{MD5}GPszWMBx6Mr8AUcsBPlGDg=="
    $a8="{MD5}Wait2V77Sml0qtb3WAoT+Q=="
    $a9="{MD5}Wait2V77Sml0qtb3WAoT+Q=="
    $a10="{MD5}4NOHi/gtRSNZBTO085c/OQ=="
    $a11="{MD5}4NOHi/gtRSNZBTO085c/OQ=="
    $a12="{MD5}8PxtxFzOpeU/6eDZbPVlrw=="
    $a13="{MD5}8PxtxFzOpeU/6eDZbPVlrw=="
    $a14="{MD5}qZrMsiY1SrcjD6MliwPE9Q=="
    $a15="{MD5}qZrMsiY1SrcjD6MliwPE9Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}