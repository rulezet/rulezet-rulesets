rule sha1_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d7eaab78f3b18d04d7dc719180d34c3ddc41c2c"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="12dea96fec20593566ab75692c9949596833adc9"
    $a3="12dea96fec20593566ab75692c9949596833adc9"
    $a4="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a5="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a6="93b61b482492ece247962250640bc5093e18639d"
    $a7="12dea96fec20593566ab75692c9949596833adc9"
    $a8="bf3f8da03de8890176727c13d39f09385aba6c25"
    $a9="363eb224f6ff8d3c5163a8805222acbf939a65b3"
    $a10="5d7eaab78f3b18d04d7dc719180d34c3ddc41c2c"
    $a11="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}