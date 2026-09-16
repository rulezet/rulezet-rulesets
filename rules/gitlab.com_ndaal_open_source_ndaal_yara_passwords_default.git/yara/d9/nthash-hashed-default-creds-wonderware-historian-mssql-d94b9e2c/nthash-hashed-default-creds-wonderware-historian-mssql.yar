rule nthash_hashed_default_creds_wonderware_historian_mssql
{
    meta:
        id = "2v6SaBmgRqz8fbANKPuUDS"
        fingerprint = "6d349c4a14f7a92eb1f77e9bbdcda4bdf805c15fdb77afd0da27c7b393452a38"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware_historian_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6ebbf2fc53ebe96eb0ba87aad43ee53"
    $a1="4f9e0f2ba1c5a7e0a9db39c098c6a10f"
    $a2="f67dc42f93657b777a90f1a31ec168dd"
    $a3="60b585537a6216ec52e87a1ec233d0fb"
    $a4="0eabf93efded5dc872c49c93bb291c1a"
    $a5="6fd36fc19e658f45fcd2aaa3a75f4a95"
    $a6="11a5bb232606d6b8adeec9aeb93739da"
    $a7="ae817f8e62c01091c5735aeace46848e"
    $a8="f850fadac0cc38dd4cc982c1e907e6b1"
    $a9="f850fadac0cc38dd4cc982c1e907e6b1"
    $a10="6d562b1084141ad8c0489ef57aedef5a"
    $a11="6d562b1084141ad8c0489ef57aedef5a"
    $a12="93a757ae594efe04c86c8809ce3c52dc"
    $a13="93a757ae594efe04c86c8809ce3c52dc"
    $a14="0ffccb88d588584f759eeaa79b12affb"
    $a15="0ffccb88d588584f759eeaa79b12affb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}