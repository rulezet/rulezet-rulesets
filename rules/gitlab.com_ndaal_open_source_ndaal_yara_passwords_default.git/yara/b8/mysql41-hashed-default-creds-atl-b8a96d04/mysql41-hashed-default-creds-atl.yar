rule mysql41_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*F13ACB16013CCF84877CED35B9DB9105C0C98A43"
    $a1="*DE597F01CC5D219FFE5896B9A8119B950125DC7C"
    $a2="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a3="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}