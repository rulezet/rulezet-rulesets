rule sha256_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9fa4e70ca1f70252d3c1b8e9fe3da17674ef57b2f44c4ddc61965d693012419e"
    $a1="f7e35c08f92d67b41addd0e5b92617d3c1b8a90124364fe78df0b4362f277e41"
condition:
    ($a0 and $a1)
}