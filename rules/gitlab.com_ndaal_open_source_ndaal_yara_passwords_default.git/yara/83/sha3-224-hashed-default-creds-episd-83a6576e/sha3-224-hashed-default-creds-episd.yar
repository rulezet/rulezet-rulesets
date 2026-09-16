rule sha3_224_hashed_default_creds_episd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for episd."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8089ced613c8ede09cb1bf48f9de39e3b42f54accb77410cce430328"
    $a1="19c2c6515bd63f05d668b5adadbffcfab9993518fd472f2da730e809"
condition:
    ($a0 and $a1)
}