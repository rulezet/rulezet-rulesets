rule sha512_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8e387cedef6ec30192678c258b1a7eee29e90337a570eb40bcd8139f56e166c1e4199bf72a70f719dc2d4109300744d4a10eca9f6b979135a61a27ec420b63e"
    $a1="0d74e7fbc3640f1ededab305ff0009ca90db7330e01002f6220ed66c319fd736a6752e0538867535b1488dcbed178ea140a20844d45e32ecfe21e8bef49a0240"
condition:
    ($a0 and $a1)
}