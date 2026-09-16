rule sha224_hashed_default_creds_accton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a1="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a2="14695dc5a4b1d81de1e07388414a7a6926b40e953879dd4f40fecb12"
    $a3="14695dc5a4b1d81de1e07388414a7a6926b40e953879dd4f40fecb12"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}