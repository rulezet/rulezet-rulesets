rule mysql323_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="43e9a4ab75570f5b"
    $a2="738d40f925fe1f9e"
    $a3="738d40f925fe1f9e"
    $a4="07ebb16747264b08"
    $a5="07ebb16747264b08"
    $a6="2e6e2da85aac3f6c"
    $a7="6434938a756bc4da"
    $a8="37c63a8040505656"
    $a9="5339dd2e60e1ee60"
    $a10="0dd3b90a1ea06fb0"
    $a11="0dd3b90a1ea06fb0"
    $a12="47488fca11464a37"
    $a13="47488fca11464a37"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}