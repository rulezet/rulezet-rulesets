rule mysql323_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="446a12100c856ce9"
    $a1="7a7eeba37575fe5e"
    $a2="4ab42b6640ccbf16"
    $a3="3c6dfccb7e5b445d"
    $a4="775b240f28521e98"
    $a5="3100ffd3503e5bed"
    $a6="57510426775c5b0f"
    $a7="01181bc63be6204f"
    $a8="3416c09974a892cb"
    $a9="760a78fe42022532"
    $a10="43e9a4ab75570f5b"
    $a11="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}