rule mysql323_hashed_default_creds_edimax
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="446a12100c856ce9"
    $a1="43e9a4ab75570f5b"
    $a2="773359240eb9a1d9"
    $a3="43e9a4ab75570f5b"
    $a4="5d2e19393cc5ef67"
    $a5="43e9a4ab75570f5b"
    $a6="28cc925241fb0235"
    $a7="6e21a8d6687d9be8"
    $a8="7525d0f416af828b"
    $a9="43e9a4ab75570f5b"
    $a10="77abdda07a1ec1d7"
    $a11="43e9a4ab75570f5b"
    $a12="446a12100c856ce9"
    $a13="57510426775c5b0f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}