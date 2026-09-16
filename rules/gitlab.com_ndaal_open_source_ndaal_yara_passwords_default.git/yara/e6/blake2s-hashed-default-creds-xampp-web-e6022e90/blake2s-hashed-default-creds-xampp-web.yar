rule blake2s_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e15bc140719497af97c6ef3a6f55ef46e47a033c357b9d65a90c77718ad938b2"
    $a1="f3e282aa4314fc5badd98ebddeb6b1fd50d0eed8f4220a528e0ab3203cb8470c"
condition:
    ($a0 and $a1)
}