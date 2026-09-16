rule sha3_512_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a1="5c2d18617a03081b0871b4d4e2d2665a5a921bc0a6da71ece733c24f2fa4124efc9b909fc5c6ebe7073240d63c1b422dc5315c9f1e95115705ac8a1a0144e742"
    $a2="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a3="90fa851acbbc24f8fc5c80a64135a61eb1782c5fbf34bb4b9f6b3e9a15c173be58c14beb18a2f6694c8f918de3ffd9ba778d1868c61bd13b9c304b908c399888"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}