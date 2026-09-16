rule blake2b_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6bce1a0350103a3c0ea2e92c31f49ad88a58bd485dfce6f57a32502f69b98a0fe7e115f82e3a382a4f13a2d0bc966b21d363dee0d4cb1254a62b72414065b9a2"
    $a1="c5faca15ac2f93578b39ef4b6bbb871bdedce4ddd584fd31f0bb66fade3947e6bb1353e562414ed50638a8829ff3daccac7ef4a50acee72a5384ba9aeb604fc9"
condition:
    ($a0 and $a1)
}