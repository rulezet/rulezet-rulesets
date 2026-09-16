rule sha3_512_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0de24605e83f581c178b5a46f0ee6e503fd58524825aa2f1ba85016044e6e28d59bf9634af903072defd03ebeb0d6e52275c7f363422f34237051a43e36542c8"
    $a1="bb203b3b09c81104473b47f394ebf05282d7249507c1ca3d296f6474ffc303d8f2e6d5c780fcce55262fc25e83c248441940966f523f13416f9aa658ce01d1e9"
    $a2="a9c97c57ba97619b12af9c65080abe9aefb0f42166fc7f7dcdc4161c1e6cc20fcc81428d0f222ef7e2c5e8b4349978055440d4e3442d3e77a052ade2e4530988"
    $a3="ff21aa55877cf49c500a8b286a5e430cd92140fc466facbf1797cf9674c38a6a2d7d7d45b69d87f76710e16f33c3b37858aa9d802d22a824578fb56c61e6ace6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}