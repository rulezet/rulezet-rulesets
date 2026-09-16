rule sha3_224_hashed_default_creds_informix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for informix."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="20109b2608f27cabfd15c663b572882fe09a950b85f97cf7f7a65cb4"
    $a1="20109b2608f27cabfd15c663b572882fe09a950b85f97cf7f7a65cb4"
condition:
    ($a0 and $a1)
}