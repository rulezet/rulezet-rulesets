rule sha3_512_hashed_default_creds_tert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tert."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c22e1905fbc76858f0fe0ea293ca8a146c0b609ced05cd308eb4d4b8272e37324a8b98d0a91dcc18ce596e4e9ef7320971756a93a4cedc5c0a5c92345f2bba68"
    $a1="c22e1905fbc76858f0fe0ea293ca8a146c0b609ced05cd308eb4d4b8272e37324a8b98d0a91dcc18ce596e4e9ef7320971756a93a4cedc5c0a5c92345f2bba68"
condition:
    ($a0 and $a1)
}