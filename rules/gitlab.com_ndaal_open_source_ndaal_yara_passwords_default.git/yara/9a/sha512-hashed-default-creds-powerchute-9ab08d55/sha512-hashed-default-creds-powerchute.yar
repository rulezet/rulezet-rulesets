rule sha512_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5079550339bcfce614f45c1628d28dd013b17ebf3bee04f5da63c3eae4d57e46d35500a0f8e00f16a3ebdf001a01517f8481737c54f02d545015e29aa41dbfd2"
    $a1="5079550339bcfce614f45c1628d28dd013b17ebf3bee04f5da63c3eae4d57e46d35500a0f8e00f16a3ebdf001a01517f8481737c54f02d545015e29aa41dbfd2"
condition:
    ($a0 and $a1)
}