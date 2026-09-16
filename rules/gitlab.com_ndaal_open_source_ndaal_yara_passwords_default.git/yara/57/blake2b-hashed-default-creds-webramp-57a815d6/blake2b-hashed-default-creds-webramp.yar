rule blake2b_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8bbe2727339a162732c045b1594e40b98425084ec453064f9ae96bc364aee3c2c03aec79dc62494a703242de8ceb400b6a03f55bfaa7fad85ae866020aaed6f"
    $a1="f75320240f9b38a2a669e483b60eecbcab967954e81dda3ac41980def81021e998bce6d8c48442b41e56ad61ac077adc58d816be6af73f93c8a6834cc92ed2ac"
    $a2="40949a4fb7ddf6b9f771ccc195bbe43c93947faa5eee0bfefba906dc03214dbc6eade1b353dd32892cd8df932d6edeba58b745e6cf5c0faad584b6d59f8215bc"
    $a3="f75320240f9b38a2a669e483b60eecbcab967954e81dda3ac41980def81021e998bce6d8c48442b41e56ad61ac077adc58d816be6af73f93c8a6834cc92ed2ac"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}