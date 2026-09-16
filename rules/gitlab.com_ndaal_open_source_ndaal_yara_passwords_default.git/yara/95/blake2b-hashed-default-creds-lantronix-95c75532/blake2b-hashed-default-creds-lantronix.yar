rule blake2b_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a1="9d0cdc80d29977b52125ac1e933f95e8d41e0de299291e4e2d8659883dd1f3b7d15c4d4422433259bbaab04eb2021d8d83d79f02fed263509b1df6eff0e1c726"
    $a2="4a5da2ebd2552455f3ccde94a636d353fa7c4aa65a16c50bf27a0672412af4d5fcadfb936e371fb75e84d89ee436faff35cb6f9951268611733b60135457cf49"
    $a3="da668ac94129340a5db3fa3d91341413bbfd477fb277272bbee5122fc1ebef04a33a76c01ed027ea066b3b7f3819f487ba6dfeaaaff9a326b49c39519ec7f474"
    $a4="3668a081b0929274a97abf15209dab17ae30a35a7751a62e5515262524cb38b5216cff0ed604cf6a8f5f5b573aa0573735764a99a6028f22e0d2ea1eaaac810c"
    $a5="02fa8d46fb2ac65ee42912604250a146af74c6b8cff1acd09bc5f460fb9850cad2674f76f982ed052c78d178196ed4c10256e2bc50e191dbb82f625cad071090"
    $a6="4a5da2ebd2552455f3ccde94a636d353fa7c4aa65a16c50bf27a0672412af4d5fcadfb936e371fb75e84d89ee436faff35cb6f9951268611733b60135457cf49"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}