rule sha1_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d8cd824e9c86f9c1c4252cb2dfd33dc2f57e894"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="72667073ecd92c5757240bb2c034538615b03cd0"
    $a3="72667073ecd92c5757240bb2c034538615b03cd0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}