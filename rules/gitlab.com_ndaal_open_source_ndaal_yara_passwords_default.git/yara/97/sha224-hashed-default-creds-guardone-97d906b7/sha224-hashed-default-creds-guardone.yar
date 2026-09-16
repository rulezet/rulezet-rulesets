rule sha224_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04ce1fd1988903ad3701106413b25d49468fc7c4562918538edc6fd6"
    $a1="a7d8eb0a6e01add341f25df790b1d7258358daa90e1c5f1925248e53"
condition:
    ($a0 and $a1)
}