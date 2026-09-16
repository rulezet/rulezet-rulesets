rule sha1_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9e16a685bc96e1717ffa25713c3defd141d24fef"
    $a1="7b202d57f214af016fe2923be40110740dd5bb91"
    $a2="fc7032fb8a794c9f1a68907cd8c1d74fa7e5dc38"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a7="12dea96fec20593566ab75692c9949596833adc9"
    $a8="a681b1a529b97fa4b4bd2214fb9a8ac6b2297fe7"
    $a9="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a10="27e3e6ea392307f86af9d0a1404b15ae27d7070e"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a12="a7b7d074bad56483bbc9c8c84d8137f206fcae2a"
    $a13="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}