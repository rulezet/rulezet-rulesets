rule sha3_224_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd99b0e06b6dc65557ced2cab067dc7c3879098114a3b83b68fa9578"
    $a1="c410bb8cb8770a4413e05d56502f282646c429ecc5eaffc9710ba01d"
    $a2="d2b80068a8b1764ebb2a9d64dd17dfb45c4b5cc7558de0c267f30b2e"
    $a3="6c997153b9824fae73b4f417bb5ee86113c6ac5c8208ad2fe2a11d71"
    $a4="d2b80068a8b1764ebb2a9d64dd17dfb45c4b5cc7558de0c267f30b2e"
    $a5="9fa45a79ebf853060beee450f43d4f3f1195e4f1486faeb5663429a9"
    $a6="d2b80068a8b1764ebb2a9d64dd17dfb45c4b5cc7558de0c267f30b2e"
    $a7="59f85285d63a00b5419b044a90248160322894be6e0f66da9543db02"
    $a8="dd99b0e06b6dc65557ced2cab067dc7c3879098114a3b83b68fa9578"
    $a9="4ce20e6bf8b909f3f1da84fa8b6fa0f73b956f68c1df8e3fe96e4b66"
    $a10="d2b80068a8b1764ebb2a9d64dd17dfb45c4b5cc7558de0c267f30b2e"
    $a11="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}