rule mysql323_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="43e9a4ab75570f5b"
    $a2="446a12100c856ce9"
    $a3="43e9a4ab75570f5b"
    $a4="5d2e19393cc5ef67"
    $a5="43e9a4ab75570f5b"
    $a6="64dfbcae5fb57c02"
    $a7="43e9a4ab75570f5b"
    $a8="4f49bf7a10041388"
    $a9="4c34074138e6e08a"
    $a10="2c20d5bd6ff371fc"
    $a11="43e9a4ab75570f5b"
    $a12="242324dd5dd2ad4f"
    $a13="242324dd5dd2ad4f"
    $a14="34e965ee7b6443e2"
    $a15="43e9a4ab75570f5b"
    $a16="1e669f5d1c42217a"
    $a17="43e9a4ab75570f5b"
    $a18="43e9a4ab75570f5b"
    $a19="0ece4be96bff92ad"
    $a20="43e9a4ab75570f5b"
    $a21="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}