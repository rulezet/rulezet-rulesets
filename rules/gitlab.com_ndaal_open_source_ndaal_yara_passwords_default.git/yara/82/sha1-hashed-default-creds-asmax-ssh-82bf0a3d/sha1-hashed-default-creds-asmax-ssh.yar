rule sha1_hashed_default_creds_asmax_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asmax_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="5bdcd3c0d4d24ae3e71b3b452a024c6324c7e4bb"
    $a3="5bdcd3c0d4d24ae3e71b3b452a024c6324c7e4bb"
    $a4="12dea96fec20593566ab75692c9949596833adc9"
    $a5="12dea96fec20593566ab75692c9949596833adc9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}