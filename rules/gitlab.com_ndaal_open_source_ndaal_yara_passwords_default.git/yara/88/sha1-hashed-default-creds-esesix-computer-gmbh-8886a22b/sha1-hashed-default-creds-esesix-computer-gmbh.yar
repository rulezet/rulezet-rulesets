rule sha1_hashed_default_creds_esesix_computer_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for esesix_computer_gmbh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58f2ca1aba8046b9f7246ffb478da7f10e972693"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1)
}