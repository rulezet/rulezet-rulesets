rule blake2b_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c46095879e7881fb1be8605f501930be2426eb03571c2aefe089118e6d5ac09a2553a2cc71642a36433a7bb835dde9a6c5aa97837deb7a119b9745dd13957150"
    $a1="b46ae04ba0582af4fdcb32c063071d75432fe07e3823bd14287f4f0984a1b8c50637de0200e72a7436e0a71c8a854ea6aee30420a167f705cae95b59968d87df"
condition:
    ($a0 and $a1)
}