rule sha3_512_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3f30619b5c9e4f9483890ad9f676583dcbfd605992d9dde1b570b88126392d01fdace49bd4c4c0f509c24fee605467f21e33d8aa41feb28ebb3f23d7641462b"
    $a1="a3f30619b5c9e4f9483890ad9f676583dcbfd605992d9dde1b570b88126392d01fdace49bd4c4c0f509c24fee605467f21e33d8aa41feb28ebb3f23d7641462b"
condition:
    ($a0 and $a1)
}