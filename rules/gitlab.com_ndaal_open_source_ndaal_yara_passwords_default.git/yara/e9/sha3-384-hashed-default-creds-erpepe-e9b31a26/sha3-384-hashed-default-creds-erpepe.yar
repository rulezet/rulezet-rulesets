rule sha3_384_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6183f37051c61abb38b39bddbd0553ad8e40bac8c9ae18ac465ea98e34b67473f92149f257802a8a426d580d1246a08"
    $a1="edb0b5aa8f7054b4666d78e7453e2d04b1e1a2bc5225a8f47993cfe9e62177e82450ac3bdb2c43cb85dd10b608ac148b"
condition:
    ($a0 and $a1)
}