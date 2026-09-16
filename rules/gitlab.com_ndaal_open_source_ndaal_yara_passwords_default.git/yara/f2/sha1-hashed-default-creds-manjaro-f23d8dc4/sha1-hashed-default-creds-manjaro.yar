rule sha1_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e1cd4518a626057b78fe077520a14ca22e73a5b"
    $a1="fdfbb71efa6115f541e469cfa9b77fbd464b07b3"
    $a2="a03a2ff7a52729deb9f4cd3e2c506118d0b5531d"
    $a3="fdfbb71efa6115f541e469cfa9b77fbd464b07b3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}