rule blake2b_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40949a4fb7ddf6b9f771ccc195bbe43c93947faa5eee0bfefba906dc03214dbc6eade1b353dd32892cd8df932d6edeba58b745e6cf5c0faad584b6d59f8215bc"
    $a1="f75320240f9b38a2a669e483b60eecbcab967954e81dda3ac41980def81021e998bce6d8c48442b41e56ad61ac077adc58d816be6af73f93c8a6834cc92ed2ac"
condition:
    ($a0 and $a1)
}