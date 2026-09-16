rule sha1_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4cf5bc59bee9e1c44c6254b5f84e7f066bd8e5fe"
    $a1="4cf5bc59bee9e1c44c6254b5f84e7f066bd8e5fe"
    $a2="98aadb37083eddd855c27feccb15dc8c5b127fd0"
    $a3="98aadb37083eddd855c27feccb15dc8c5b127fd0"
    $a4="12dea96fec20593566ab75692c9949596833adc9"
    $a5="12dea96fec20593566ab75692c9949596833adc9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}