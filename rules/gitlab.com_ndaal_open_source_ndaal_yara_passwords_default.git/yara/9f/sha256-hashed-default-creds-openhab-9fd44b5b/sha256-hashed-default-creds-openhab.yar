rule sha256_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9569036ca5c65a5cfb0a070144e999c2a322f5711b0b05988b17437cb29be24b"
    $a1="9569036ca5c65a5cfb0a070144e999c2a322f5711b0b05988b17437cb29be24b"
    $a2="4f61a0fd056bc0fd8231899ec4d9f9ca06af0dec895b2a3b0773f6fbc1c99776"
    $a3="b1d3dc2cc0a1114599cc2a7571548b516b2168657b7d2ac19268506e80defdca"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}