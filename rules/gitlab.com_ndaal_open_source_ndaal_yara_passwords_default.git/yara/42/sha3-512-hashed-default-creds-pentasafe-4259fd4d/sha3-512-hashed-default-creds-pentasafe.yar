rule sha3_512_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="648c1a777cf9b02bf3747c924f13d4667abbbdc66f1d0623d13f4ab477f185bd3010962322dce1fd5fb853a8b9a5df90cde9b4e14e81a7d5ddf3468f196b03b4"
    $a1="7b6195df2506e822a6d321a6c564f6be238a28e41cc7b7cc7477b11b552b004921e1b38d975629769b55a787b31748e0b5339c92ad8db535aca5f9d88c3fe19f"
condition:
    ($a0 and $a1)
}