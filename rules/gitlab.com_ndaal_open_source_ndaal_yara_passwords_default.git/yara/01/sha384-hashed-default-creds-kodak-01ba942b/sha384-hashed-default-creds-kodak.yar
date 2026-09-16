rule sha384_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9010057c7aff690a8e7df72f2a8e88c73506d6e7082cb1a6cb5c382f771a78f33427a3cf3dbad6f240179492766dd8c9"
    $a1="dcdbb7cae4ba4c301f747cacc237d32de08cc72933e8392fd2f7e0dbe7e9dbace37994945d6877b367f26369d11f9f6b"
    $a2="9010057c7aff690a8e7df72f2a8e88c73506d6e7082cb1a6cb5c382f771a78f33427a3cf3dbad6f240179492766dd8c9"
    $a3="2efcd5ee58d1ea5cf9fe574675efa4d26d3da99a225ff16f29264604a7450b1370882d38e77170119aaa9e86a9285ca1"
    $a4="9010057c7aff690a8e7df72f2a8e88c73506d6e7082cb1a6cb5c382f771a78f33427a3cf3dbad6f240179492766dd8c9"
    $a5="08f5ddd2951273523ace0db98a5afaaa471b57f9f385f936793990532aa698b20e3d600e773d7e462925e9f915fe764b"
    $a6="d141b7e90779b15793cce4046f86faa9d32950d7e542761874460231eb94bcfec5d37b5f87581cba666973a1b22aa4aa"
    $a7="53c04f7aae30ba990c9400179ad890679f601ccfad0f3d54f422f7fbf6d5f861af85ee102f43f9e2c0b8cb7f6c0a181b"
    $a8="4db800350e79f01139d3565cdfd6534c58a1172a70213cc096b7b7d8e314694559f7dbcb410f65addd9b18b87916e81e"
    $a9="4db800350e79f01139d3565cdfd6534c58a1172a70213cc096b7b7d8e314694559f7dbcb410f65addd9b18b87916e81e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}