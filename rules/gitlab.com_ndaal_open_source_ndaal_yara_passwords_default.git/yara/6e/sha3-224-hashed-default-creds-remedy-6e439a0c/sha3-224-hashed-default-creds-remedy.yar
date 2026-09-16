rule sha3_224_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c91f674025e3bb73a507f7d6ca9c739408d531d738cc7a16fbcc9854"
    $a1="a9303751e638eb7e798d1aad0711df288906a1ebca2ef6f856bc741c"
condition:
    ($a0 and $a1)
}