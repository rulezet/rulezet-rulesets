rule sha512_hashed_default_creds_hosting_controller
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hosting_controller."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="87df9fc25ad8616fc92a0b8c06f645604e8841db3ee66a9a39a553e5c04755fca9c92207d5182da77f7da4b63169475b1ced857a73af51914f2c7fb4740c3755"
    $a1="a6a48168431dd674ec59d95e173a01f1be81b1d49f2a286362d738b5464a207ed2f3d00ba7fde401d20a17de6c9707d0eb57c9cf1c157d7dcad141a5bfeeae4a"
condition:
    ($a0 and $a1)
}