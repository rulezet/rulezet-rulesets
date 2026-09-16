rule sha3_224_hashed_default_creds_mro_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mro_software."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a1="36f617e4518035a4b44bfe7343172c077cb95ee2f760fa10a76570f8"
condition:
    ($a0 and $a1)
}