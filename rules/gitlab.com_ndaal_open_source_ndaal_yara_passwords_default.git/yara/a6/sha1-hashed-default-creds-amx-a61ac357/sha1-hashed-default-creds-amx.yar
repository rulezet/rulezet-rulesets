rule sha1_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3cacfd9c7fb9cb4cb9e97f95107e5e56bf020c5d"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a4="286b9b7b50ab89e3397b4df540021b531f457f7f"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a7="f4de804fa42551cb24dfef3529f045486efa8a9c"
    $a8="3cacfd9c7fb9cb4cb9e97f95107e5e56bf020c5d"
    $a9="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a10="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a11="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a12="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a13="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a14="a7c9e011698f0aac3d42b3f2aa08ff43568fa291"
    $a15="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}