rule sha1_hashed_default_creds_linksys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for linksys."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f626a2f5ceb8f22553443073aa39616dbc77708"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a5="169e151484edcb2aaa9b38047bd97386b6c1ca2b"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a8="2bc455f47c2bdf3b53a7a3a94d883524fb902f35"
    $a9="12dea96fec20593566ab75692c9949596833adc9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}