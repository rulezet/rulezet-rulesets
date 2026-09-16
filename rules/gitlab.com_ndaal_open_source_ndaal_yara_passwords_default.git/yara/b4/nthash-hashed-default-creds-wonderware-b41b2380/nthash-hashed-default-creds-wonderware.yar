rule nthash_hashed_default_creds_wonderware
{
    meta:
        id = "3Rg21cRDNzraIFtD7v7FHc"
        fingerprint = "78c066be209d54a175c67d9ffc8c66872b761ac6f41e59c3324572fe5b5bec82"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0345bc16d621fcecc661764e2b7a73b0"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="f67dc42f93657b777a90f1a31ec168dd"
    $a3="60b585537a6216ec52e87a1ec233d0fb"
    $a4="f67dc42f93657b777a90f1a31ec168dd"
    $a5="6d562b1084141ad8c0489ef57aedef5a"
    $a6="a6ebbf2fc53ebe96eb0ba87aad43ee53"
    $a7="4f9e0f2ba1c5a7e0a9db39c098c6a10f"
    $a8="f850fadac0cc38dd4cc982c1e907e6b1"
    $a9="f850fadac0cc38dd4cc982c1e907e6b1"
    $a10="0eabf93efded5dc872c49c93bb291c1a"
    $a11="6fd36fc19e658f45fcd2aaa3a75f4a95"
    $a12="93a757ae594efe04c86c8809ce3c52dc"
    $a13="93a757ae594efe04c86c8809ce3c52dc"
    $a14="11a5bb232606d6b8adeec9aeb93739da"
    $a15="ae817f8e62c01091c5735aeace46848e"
    $a16="0ffccb88d588584f759eeaa79b12affb"
    $a17="0ffccb88d588584f759eeaa79b12affb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}