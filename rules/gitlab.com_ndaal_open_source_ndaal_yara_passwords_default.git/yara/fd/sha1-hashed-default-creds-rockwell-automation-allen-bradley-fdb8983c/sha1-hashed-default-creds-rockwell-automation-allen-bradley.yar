rule sha1_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="d01d8b3ceb99d61b86b94b86913a7aed6bcd799a"
    $a5="41ae8cf7f1ec7edf8c7cc1f77e800593e14aa265"
    $a6="d01d8b3ceb99d61b86b94b86913a7aed6bcd799a"
    $a7="e4dd3fc549a992d934b9aecc0d37c098c54cceb7"
    $a8="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a9="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a10="a3a2288e8cc27cea8f702f2caeb195768e528c0a"
    $a11="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a12="05f0b07469ab1af92a36607ae9475249e288b3b4"
    $a13="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}