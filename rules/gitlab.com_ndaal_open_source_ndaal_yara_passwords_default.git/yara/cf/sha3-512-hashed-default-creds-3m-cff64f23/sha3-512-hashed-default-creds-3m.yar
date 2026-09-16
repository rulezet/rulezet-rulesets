rule sha3_512_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15a53dbbfb963a99dc174afd5d0860d072134f35ce9e7c53370cd5d00db50b6ae58dc4cc0473672216f5a04a7670cc021cf707bdec518e1cb15107e25167e1b4"
    $a1="15a53dbbfb963a99dc174afd5d0860d072134f35ce9e7c53370cd5d00db50b6ae58dc4cc0473672216f5a04a7670cc021cf707bdec518e1cb15107e25167e1b4"
condition:
    ($a0 and $a1)
}