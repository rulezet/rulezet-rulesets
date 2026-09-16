rule sha384_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eae8b4a8fd1c1b1d803368c19b8ab175561f65b06378c1797a61aaca69a516a103e03a2bbe2475c66650a9d87d26e1a1"
    $a1="eae8b4a8fd1c1b1d803368c19b8ab175561f65b06378c1797a61aaca69a516a103e03a2bbe2475c66650a9d87d26e1a1"
condition:
    ($a0 and $a1)
}