rule sha3_512_hashed_default_creds_schneider_m340ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_m340ftp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6fc99f5ae5ba7605fd6ae2d3d2b5c56821ffb0a9e1f257ed31eaee5bc374919bd8aa81fdb7ab9cfae9d0a7de7cd98f2ec45c5fa9998eb04ddfdc01e754f6411a"
    $a1="cb3b953d592297d5ca7659f59e3c0dc1c7a273b851446855dd90854e14606e96b355d9b419766493a56cd06e28d6bf49849bf33951787d00af188f2663e18df8"
condition:
    ($a0 and $a1)
}