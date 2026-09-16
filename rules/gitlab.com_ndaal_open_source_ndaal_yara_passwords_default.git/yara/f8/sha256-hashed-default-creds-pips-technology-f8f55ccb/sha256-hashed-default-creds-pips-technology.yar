rule sha256_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47d89b52f9cab096f8244daa587658709dc3b5bc138f838e1d5d3563cc798894"
    $a1="47d89b52f9cab096f8244daa587658709dc3b5bc138f838e1d5d3563cc798894"
    $a2="75af9aa69e409c7eda5e19b19f6b194bc3cd0cbfd932b37397652a1ca9c0f277"
    $a3="75af9aa69e409c7eda5e19b19f6b194bc3cd0cbfd932b37397652a1ca9c0f277"
    $a4="b6b422bbcf4833221ded639a0de48d239e6ee04ab5e3bf6f5de0e043341e3cc5"
    $a5="b6b422bbcf4833221ded639a0de48d239e6ee04ab5e3bf6f5de0e043341e3cc5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}