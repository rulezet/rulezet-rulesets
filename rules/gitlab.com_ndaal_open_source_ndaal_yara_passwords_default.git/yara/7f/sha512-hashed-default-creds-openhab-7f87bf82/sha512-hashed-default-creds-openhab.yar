rule sha512_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ef69fb29f0b9e7a8990ffa741043f1d85ccc8c871efd539b3fe8303a0999c0cf140aff536c0164b5a4a6215857be5a7472b927622b053b4ddd17899707308df"
    $a1="1ef69fb29f0b9e7a8990ffa741043f1d85ccc8c871efd539b3fe8303a0999c0cf140aff536c0164b5a4a6215857be5a7472b927622b053b4ddd17899707308df"
    $a2="21740f19bb686e2d821b6f4e6754f09d4f80769fa5257d20777ea09344c4a52d6cd1fbcd8e79ecd95d25c74c7570a39936d8e8c17fb3eec649216c1fd7deaf24"
    $a3="d8696789560c1493ce4c1aaafd1ed5a83a0a777f57fef3965d922df524dc524aa0bc3e82b1acec25610af520819ef95112c5776ce14d973e7e0bb3fc9f3f1e45"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}