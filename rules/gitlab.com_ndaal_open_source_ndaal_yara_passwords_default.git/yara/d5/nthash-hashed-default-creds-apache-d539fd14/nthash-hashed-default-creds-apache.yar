rule nthash_hashed_default_creds_apache
{
    meta:
        id = "UJtyHGJZEXOGAOyYb2Km3"
        fingerprint = "252f68a24414d2e87ecfdae24023e390e85bfafefa337feda4bd5ff7b6cc4302"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ead38134b84c88f62c68b60521fccd5"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="1e0154a9860f303dab543376a058676b"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="2455f99b8add81043a8b3e54684a22e7"
    $a7="4f3cc040ba06cc0a79df1189b75cc24b"
    $a8="d8ce5e0233e3e6aa0fff4040bebc8231"
    $a9="d8ce5e0233e3e6aa0fff4040bebc8231"
    $a10="2455f99b8add81043a8b3e54684a22e7"
    $a11="329153f560eb329c0e1deea55e88a1e9"
    $a12="329153f560eb329c0e1deea55e88a1e9"
    $a13="329153f560eb329c0e1deea55e88a1e9"
    $a14="2455f99b8add81043a8b3e54684a22e7"
    $a15="1e0154a9860f303dab543376a058676b"
    $a16="1e0154a9860f303dab543376a058676b"
    $a17="1e0154a9860f303dab543376a058676b"
    $a18="1e0154a9860f303dab543376a058676b"
    $a19="a09f29e47e8e45492e84a54855598485"
    $a20="1e0154a9860f303dab543376a058676b"
    $a21="d8ce5e0233e3e6aa0fff4040bebc8231"
    $a22="0ec6d486dec1f4e3d8333e24e07330b9"
    $a23="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}