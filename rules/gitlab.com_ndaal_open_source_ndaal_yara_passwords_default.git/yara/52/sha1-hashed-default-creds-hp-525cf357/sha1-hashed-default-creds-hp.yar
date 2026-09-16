rule sha1_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="e38b4902ecb81982a6e533aef793c7b86ee42680"
    $a3="c65f99f8c5376adadddc46d5cbcf5762f9e55eb7"
    $a4="124448559f477599791f2068f131dbe6c9a4e457"
    $a5="fb434d38698832a599e41e3ec55495f886e28cbb"
    $a6="a82e126e862141d0ecb800cbd89c34de54eb3b87"
    $a7="fb434d38698832a599e41e3ec55495f886e28cbb"
    $a8="ef991ef607e69dfdd1198343b76141a8fb4c235f"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="f2231d2871e690a2995704f7a297bd7bc64be720"
    $a11="e47b9b1021034a56b7d5f70d92d0481524e78f69"
    $a12="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a13="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a14="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a15="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a16="966e04d925500e6c35ed8fa8028f33fa3bdb9dcb"
    $a17="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}