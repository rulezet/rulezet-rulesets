rule nthash_hashed_default_creds_prtg
{
    meta:
        id = "6sRkR6oz5knh9QKOQH9gtp"
        fingerprint = "d0b9cd8127f388b951f37ab705b4f3ab8ff0596aca1f308c155fbc47c53e213a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for prtg."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8e98af6116f0aa66c4d9b31047c2dc76"
    $a1="8e98af6116f0aa66c4d9b31047c2dc76"
condition:
    ($a0 and $a1)
}