rule blake2s_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e3ed214cbf925e45a33acc2f691ec692b38564ef66d2f80b75dcb16710d9cc6"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="d65713daf4bfd4cec7b745476c42fcdb7f34045f314f4842f6e47dcc25d27ab9"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="e9906881fc284dae8238878c1a409311519713023291779b53d8636234c9a735"
    $a5="97c665ef42239cceba9e65db0a1123f2b3de1891ba4462778304b1e07c4103a7"
    $a6="c396f26e2507ca2b9d5723d5e649f705767beb0d4326572f45afb469faa21151"
    $a7="deccbbaa43384c8f3618af30729423bce158c9e716a394cdb960da011c4390d8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}