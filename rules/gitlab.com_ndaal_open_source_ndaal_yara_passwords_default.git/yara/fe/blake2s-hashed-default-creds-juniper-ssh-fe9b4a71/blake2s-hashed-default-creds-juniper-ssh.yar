rule blake2s_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bb48bdae67206a493787b69821008fcd6249d013125972db3660e75ab6f3c884"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="e1bcef28ec1e2de5e2dcb74a5c8b52190c44c17ded9c8f4a2482e8cb8299459a"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a7="9ca80bd0953938baf509f7bd03fb009d336cbef99edb07037ffde53afef33d26"
    $a8="64e6c635432e4f47869c2d062ac7738cc60facd584184c89e2e5614b9d00d666"
    $a9="64e6c635432e4f47869c2d062ac7738cc60facd584184c89e2e5614b9d00d666"
    $a10="6cf89fc9d03c853b527101b230e9c407518587ea1e5a02acf8a04d503011a009"
    $a11="6cf89fc9d03c853b527101b230e9c407518587ea1e5a02acf8a04d503011a009"
    $a12="eb43801c2bbc902aa1a198866e32ded43c5004c7c47954b04f003d287d2356cd"
    $a13="7b866d188933ccc5dfc6f79bd6366c759f7661ff500626bc1b013b6947eb5831"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}