rule mysql41_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a1="*0C1648C40981C5CA7B0410D41CB3ED8C43E05388"
    $a2="*B415DD9C4FB5EF59FE80C4FEBC1F9C715E6E97C4"
    $a3="*96D6A0C2685F450571C6500185A4FF596EF22098"
    $a4="*49D3CEBD189B8C5D4A47C975133BB2357A327585"
    $a5="*497F081B3750057FE652584E2611798B53DB6389"
    $a6="*B415DD9C4FB5EF59FE80C4FEBC1F9C715E6E97C4"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}