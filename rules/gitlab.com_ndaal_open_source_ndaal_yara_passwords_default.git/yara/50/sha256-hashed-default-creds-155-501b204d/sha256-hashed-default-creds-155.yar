rule sha256_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b544267fc76fc36f8360339b3af58e150a6658822c76c1d7bac00d78d838d62"
    $a1="0b8e9e995d8d77f1e4770f0f79665aee6f3f70247b3735422daba73df4c3096f"
    $a2="fe9bbd400bb6cb314531e3462507661401959afc69aae96bc6aec2c213b83bc1"
    $a3="fe9bbd400bb6cb314531e3462507661401959afc69aae96bc6aec2c213b83bc1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}