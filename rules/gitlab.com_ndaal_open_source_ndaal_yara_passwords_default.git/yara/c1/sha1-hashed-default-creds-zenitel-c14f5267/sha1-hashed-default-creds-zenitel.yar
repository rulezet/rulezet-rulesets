rule sha1_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03494a24ed5337acd1ebf90252e0456c384040ad"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="082d67dc6c68a645871573e4f01807bbc2900da8"
    $a3="b521caa6e1db82e5a01c924a419870cb72b81635"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}