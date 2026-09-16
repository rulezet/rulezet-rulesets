rule blake2s_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="bfede1e34bf2c349910b30ff13ff8f2ee4acad4c26766d0e2714987a8fb995d3"
    $a3="90dede0a7e592fe2c9c5bbd1dbcddd9de3a0247b52569068bf28079ed98b5f5e"
    $a4="d615da88cf76d7901486b4193398d83bdc378f16c0feaf0e6b0a2635a298b547"
    $a5="6935dc80a6d5f6c34f57960c03769bdc4b997f7de78005d7211da593b7b74733"
    $a6="d1a6e6a24703aba7f1a90b821b18ae32c5f446253384528be7a5f9f215198db9"
    $a7="6935dc80a6d5f6c34f57960c03769bdc4b997f7de78005d7211da593b7b74733"
    $a8="6f6a3d2eb1a546dc6128fdfa48f9996c504837e7ea2b6be72c0da2c63085927f"
    $a9="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a10="b9bbb73c490b862e77461f5b12b60ae92c5460901991c39ce31b7da24f1d878f"
    $a11="5616213d19391447e21fd7a3119ebd9ebf17ef493d3760ef89a4a769b62729a4"
    $a12="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a13="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a14="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a15="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a16="e0bd0f313e0fb13640eb5060fb0e8a9cd501c4aa7d82ad39aebf35829b3d968e"
    $a17="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}