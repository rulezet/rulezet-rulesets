rule mysql41_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*047E18A4C8E3777114B166A4EF752F2E28E5362A"
    $a1="*34E8D02C361F409EFA12A0DC2D59029648DCF5D5"
    $a2="*B09F1B2C210DEEA69C662977CC69C6C461965B09"
    $a3="*B09F1B2C210DEEA69C662977CC69C6C461965B09"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}