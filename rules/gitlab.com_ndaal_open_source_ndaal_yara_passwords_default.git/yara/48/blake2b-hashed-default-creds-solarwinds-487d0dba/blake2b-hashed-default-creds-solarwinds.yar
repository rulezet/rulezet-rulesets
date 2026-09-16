rule blake2b_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a6e0cbfc1e23fd6b43d99b60bc40a5d0b0c8596a00b62b1bfa6572d7a90489b8d82e98706a58dba9f4858acadac0ac71c4c780e3273ce1019edef5a89444876"
    $a1="fd055ae00ef38a75c9bfd2c48cea5104d8ab745c2627de58de9f5cf924882d590ae72008a94df81e33e49eaa9db63357cf2efdff6eacb0a5447d68bfdd17ea4e"
    $a2="327166285b7a2ee885dd9d93c733ae8dfc3bc9e9d5788ad241561c3b92ca4f5ea4ff840dac2734ed6dfacf343df631f93b228d8187a76dfbe51d13c28049233f"
    $a3="327166285b7a2ee885dd9d93c733ae8dfc3bc9e9d5788ad241561c3b92ca4f5ea4ff840dac2734ed6dfacf343df631f93b228d8187a76dfbe51d13c28049233f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}