rule sha3_256_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="be87f99a67e48ec4ec9f05b565f6ca531e24b9c71a62cfd3a58f54ebc60115ea"
    $a5="708c415af41c02c2da22e3db678cbfd2918bb2f82bfbba34fc792af1f98596e1"
    $a6="a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67"
    $a7="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a8="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a9="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a10="d2102befa98bf91c59cb8edeb04feb74e77d07d5417bc036b976176c9f6457a8"
    $a11="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a12="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a13="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a14="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a15="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a16="97912135444a7a57c188aba364e445ba5cf006fc23a85efca243b8ace433922d"
    $a17="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a18="25c05a20fc664fe2e343d272f4d42d24dcb6756614b554fd862a51c28052364a"
    $a19="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a20="25c05a20fc664fe2e343d272f4d42d24dcb6756614b554fd862a51c28052364a"
    $a21="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a22="567166287d1e3e1c701262d1b36e3f55af484d45b531501d0a12b686a81e6f80"
    $a23="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}