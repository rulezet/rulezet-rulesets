rule sha1_hashed_default_creds_compaq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for compaq."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a2="1c69ad94f31c57fe2e80193988145c54a7b9cfdb"
    $a3="67532ddaa01193e3a132133853e693f64ead9d72"
    $a4="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a5="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a6="fe96dd39756ac41b74283a9292652d366d73931f"
    $a7="fe96dd39756ac41b74283a9292652d366d73931f"
    $a8="61c9b2b17db77a27841bbeeabff923448b0f6388"
    $a9="12dea96fec20593566ab75692c9949596833adc9"
    $a10="12dea96fec20593566ab75692c9949596833adc9"
    $a11="12dea96fec20593566ab75692c9949596833adc9"
    $a12="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a13="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a14="c1f46c805200d800a0c0185b33334b263d34c7ed"
    $a15="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}