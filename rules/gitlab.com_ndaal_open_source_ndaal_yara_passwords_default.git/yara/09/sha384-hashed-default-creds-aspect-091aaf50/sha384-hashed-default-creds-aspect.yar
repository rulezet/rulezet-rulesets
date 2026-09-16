rule sha384_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19ea73c1d4b4071f2eafba548e5d49c07bcc678f6c20735f5ab4158b32ce5bd16137b11f762b77fbf07c5468b8f29fda"
    $a1="53b85072d746d6436f988e6dd79617edfb83ce678d900efe95c64cf4f5706a17d57cdc5dd71b5979d51e5379e4f20323"
condition:
    ($a0 and $a1)
}