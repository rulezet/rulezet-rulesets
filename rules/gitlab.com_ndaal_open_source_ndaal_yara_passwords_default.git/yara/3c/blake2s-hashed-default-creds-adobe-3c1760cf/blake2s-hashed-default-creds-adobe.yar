rule blake2s_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="d49b4d32ed403526cc84ff6a1488f72cbe6883cef104fcf00387cbe9e27f2aae"
    $a3="d49b4d32ed403526cc84ff6a1488f72cbe6883cef104fcf00387cbe9e27f2aae"
    $a4="e06f7374ab7dc222d4086d9afc52ba24ddc4ac30018b423a2356ac6eb9fddaff"
    $a5="e06f7374ab7dc222d4086d9afc52ba24ddc4ac30018b423a2356ac6eb9fddaff"
    $a6="677a88031e7189bdabfd74e5d736f7b0a9069deb15b88f7f5d85d7234cb7a481"
    $a7="d9fe28194265c84ad597e00165e52f3a2e99a3c63e49bfec11c039d06eb295e2"
    $a8="4796448e5d4927d61af5a2ff073fb25047bf891ff43a2f0637021307a4b5f90b"
    $a9="9c5c68c24419b1b6388b6aa6e8918e613da4538f8376dc6ae106cd45a598f456"
    $a10="92a3801d682634e865b12928034cee4ffa7fd42ff464c3098c0acac188133642"
    $a11="92a3801d682634e865b12928034cee4ffa7fd42ff464c3098c0acac188133642"
    $a12="94d3f970ceb5bb584e0d484217efd29223a545da1f0921ba26ddad2767dc9e2e"
    $a13="94d3f970ceb5bb584e0d484217efd29223a545da1f0921ba26ddad2767dc9e2e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}