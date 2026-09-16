rule nthash_hashed_default_creds_d_link
{
    meta:
        id = "3OUrkuDT5iMoYdPANDMuKG"
        fingerprint = "660883a2ff28895363481db8e89f7eae5788b9d6eca1493b8cf607c0d4493c3b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="ddc7fb79de1a6b6e9efe6d0196f31322"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="0e671b4301dd9a9d158ef5b519840bd5"
    $a9="15c2864b8c73079f372eb1f0e77067ed"
    $a10="db51013b2730e1f16df6db7c3a73ad60"
    $a11="209c6174da490caeb422f3fa5a7ae634"
    $a12="876f827c2d6b791883681cbd6f59c122"
    $a13="876f827c2d6b791883681cbd6f59c122"
    $a14="d7b01f802408113c32c069edba40c406"
    $a15="209c6174da490caeb422f3fa5a7ae634"
    $a16="f544adb3063108430ee40fe5a4703a0b"
    $a17="209c6174da490caeb422f3fa5a7ae634"
    $a18="209c6174da490caeb422f3fa5a7ae634"
    $a19="a761f58da397eee687624761af01e826"
    $a20="209c6174da490caeb422f3fa5a7ae634"
    $a21="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}