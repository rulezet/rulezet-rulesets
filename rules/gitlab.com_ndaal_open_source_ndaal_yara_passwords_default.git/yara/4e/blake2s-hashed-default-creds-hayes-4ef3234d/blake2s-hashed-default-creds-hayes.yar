rule blake2s_hashed_default_creds_hayes
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hayes."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1254c5e4c16e4cd9a72ee34235a07d4560140909201268f1970797ab1ea2d502"
    $a1="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
condition:
    ($a0 and $a1)
}