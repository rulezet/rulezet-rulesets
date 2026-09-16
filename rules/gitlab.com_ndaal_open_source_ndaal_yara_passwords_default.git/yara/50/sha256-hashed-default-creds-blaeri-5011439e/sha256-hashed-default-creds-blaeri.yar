rule sha256_hashed_default_creds_blaeri
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for blaeri."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11638794f5a56a79a897b913ece5183b74de53f2553bf81214edd7c212051239"
    $a1="245dc8004d15c6b26faae1c7ac5421f3c1fd417cbbd632cb197dcaf5ea96140c"
condition:
    ($a0 and $a1)
}