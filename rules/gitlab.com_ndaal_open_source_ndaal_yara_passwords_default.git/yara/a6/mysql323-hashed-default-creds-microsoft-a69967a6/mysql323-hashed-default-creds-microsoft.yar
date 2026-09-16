rule mysql323_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a486e7929011a28"
    $a1="6013e7eb6ba4d801"
    $a2="43e9a4ab75570f5b"
    $a3="43e9a4ab75570f5b"
    $a4="15f73cd91718b388"
    $a5="15f73cd91718b388"
    $a6="58f7ee435f925abe"
    $a7="58f7ee435f925abe"
    $a8="01181bc63be6204f"
    $a9="01181bc63be6204f"
    $a10="4d75470c619b482b"
    $a11="4d75470c619b482b"
    $a12="0aaf5aba5ede3e17"
    $a13="389e2a471f7e3936"
    $a14="7c322543213bc140"
    $a15="7c322543213bc140"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}