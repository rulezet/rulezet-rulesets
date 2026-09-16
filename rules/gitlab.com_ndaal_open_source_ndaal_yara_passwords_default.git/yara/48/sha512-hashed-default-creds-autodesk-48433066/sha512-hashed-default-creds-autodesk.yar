rule sha512_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2edd680c41415d407530aa382808d33cb2fdc7fd43915831eea4a5177cd1ffbcb884cc1488ac901227aaf7e893654691b8949f8a7ec6e89592c14f8c09db8d5"
    $a1="c2edd680c41415d407530aa382808d33cb2fdc7fd43915831eea4a5177cd1ffbcb884cc1488ac901227aaf7e893654691b8949f8a7ec6e89592c14f8c09db8d5"
condition:
    ($a0 and $a1)
}