rule sha1_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="16a9a54ddf4259952e3c118c763138e83693d7fd"
    $a2="8eec7bc461808e0b8a28783d0bec1a3a22eb0821"
    $a3="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a4="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a5="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}