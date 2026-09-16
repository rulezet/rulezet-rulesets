rule sha3_512_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="333abe9a0c5a6e5c2f708742138aa520160f9ca27bcfde7d78ae254ff2473034485e3283a485e56c1c9f3c2df2fdb3521ff5696f8c6d208fb5c662a2d149f503"
    $a1="9a6da13771937cc2a8c3d3cec5b5829c6b063404c12735805d5ea48d2ae818ca61d665b0cac0083e928de62eb5059709b03240c5cefc49222f5483c3c7ba3f1f"
condition:
    ($a0 and $a1)
}