rule sha384_hashed_default_creds_firebird
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for firebird."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dedd9fbb2b8711a25753f2faddfd4c7478f584e8f9ee89328f3fdfab770ee19abcc7fbae828335f73500137ee4091b9"
    $a1="253553fe01d9d5666fbd3cadacd95189085b9d922b25aa01fae15858a56db818e75f5afe1216b0bbffcc23bb3e28dc54"
condition:
    ($a0 and $a1)
}