rule mysql323_hashed_default_creds_zyxel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="446a12100c856ce9"
    $a1="43e9a4ab75570f5b"
    $a2="446a12100c856ce9"
    $a3="446a12100c856ce9"
    $a4="446a12100c856ce9"
    $a5="08f96389786a51d4"
    $a6="446a12100c856ce9"
    $a7="67457e226a1a15bd"
    $a8="08c526425edec080"
    $a9="6dc6b1697171b892"
    $a10="58f7ee435f925abe"
    $a11="446a12100c856ce9"
    $a12="43e9a4ab75570f5b"
    $a13="43e9a4ab75570f5b"
    $a14="19225735263cd3c5"
    $a15="43e9a4ab75570f5b"
    $a16="74f04af90f0a9cf3"
    $a17="4077eb0b03ddce3b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}