rule mysql323_hashed_default_creds_digicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicom."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="67457e226a1a15bd"
    $a2="79d9806e515b15ca"
    $a3="43e9a4ab75570f5b"
    $a4="5d2e19393cc5ef67"
    $a5="1a486e7929011a28"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}