rule sha224_hashed_default_creds_cellit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cellit."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10872985bb31edc6ee132c33b52a046ef90246fe8ac9c9943e965d6b"
    $a1="10872985bb31edc6ee132c33b52a046ef90246fe8ac9c9943e965d6b"
condition:
    ($a0 and $a1)
}