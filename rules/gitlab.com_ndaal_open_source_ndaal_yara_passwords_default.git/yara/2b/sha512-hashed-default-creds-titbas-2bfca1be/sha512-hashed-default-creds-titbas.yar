rule sha512_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d2aa3cf52c1169c42e1c03341f4ed0e7d709d3c4bbfd5ceb1e1dc1ab66dcac4c98721c4c07ab590654404e21296bd15fd3ef70b6a536a2fec58dfc3f5c8ffc8f"
    $a1="6d54fff35aabeaa7b70caaf0da953d6fc003f9257da3ce74aa14861123732b8bea9f2df6c2e3fdb4dfe7f6b9f06b836b46f715836bb9c7513002a48689687209"
condition:
    ($a0 and $a1)
}