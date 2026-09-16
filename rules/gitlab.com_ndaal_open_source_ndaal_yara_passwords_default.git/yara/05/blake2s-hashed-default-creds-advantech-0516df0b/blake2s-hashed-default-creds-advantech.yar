rule blake2s_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="a59a11342336477b3b1ea828ceaf6f2f2df4fdf78175a8acea26d8e389791993"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="cd47e74fbcd689a3a1a85c0bd38cbd1fa05afe4c8f570cc254bfe2b21a19e1b1"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a6="cd47e74fbcd689a3a1a85c0bd38cbd1fa05afe4c8f570cc254bfe2b21a19e1b1"
    $a7="0a3109efa9dd4bf2cf373f62ec66b3c710146fbe51db336f809fa1815758b8c5"
    $a8="cd47e74fbcd689a3a1a85c0bd38cbd1fa05afe4c8f570cc254bfe2b21a19e1b1"
    $a9="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a10="cd47e74fbcd689a3a1a85c0bd38cbd1fa05afe4c8f570cc254bfe2b21a19e1b1"
    $a11="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}