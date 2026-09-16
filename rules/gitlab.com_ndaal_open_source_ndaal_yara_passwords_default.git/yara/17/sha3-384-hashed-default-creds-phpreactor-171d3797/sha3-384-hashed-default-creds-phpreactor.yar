rule sha3_384_hashed_default_creds_phpreactor
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3993a490b023d2df8561c7f088190fb36f5e767cf7100aa3a33b52d3beb91101003672583c7079b9771633cc5e28e334"
    $a1="a4516ab200f5ed7ddb33b6e53a9f8a3d8c028955e0d1f99cab427e4d309dcdbe258a445ed54be33e2d0ba7b247496654"
condition:
    ($a0 and $a1)
}