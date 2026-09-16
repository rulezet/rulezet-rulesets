rule sha1_hashed_default_creds_zyxel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a4="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a5="30e0c5f0ec5359f21e34af3691470c1b91865295"
    $a6="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a8="109e93ccc8ba9cda80aaf71c76c469d5dc62f96f"
    $a9="85b8495630ecde325a2a9e50f0a0e40130998067"
    $a10="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a11="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a12="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a13="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a14="39dfa55283318d31afe5a3ff4a0e3253e2045e43"
    $a15="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a16="aaf2858026a07d7f68a717da9b109234c59a29da"
    $a17="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}