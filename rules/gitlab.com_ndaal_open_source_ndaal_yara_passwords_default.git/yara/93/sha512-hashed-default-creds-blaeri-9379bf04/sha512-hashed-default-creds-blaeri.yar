rule sha512_hashed_default_creds_blaeri
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for blaeri."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="332d4a3c66da88c1a4dc0a522b0f5afdcc4fad3646ce0e3c65fc606d0fc913817b97576dc7d98c69391ac3925d16c01f3827a45c9a7352d819b14bb5b8c95f59"
    $a1="836acd2addb8cef4e48237ed8e7e4dbea814c991f8519f753147e2ab112bdd2d47c0432c60d0a68478aa9898c2c97fb70a60fd745d5bf61af294120bed04aa5a"
condition:
    ($a0 and $a1)
}