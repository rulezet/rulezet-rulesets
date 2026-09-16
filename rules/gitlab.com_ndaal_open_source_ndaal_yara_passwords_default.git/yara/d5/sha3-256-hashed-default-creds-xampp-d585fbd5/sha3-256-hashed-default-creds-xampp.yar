rule sha3_256_hashed_default_creds_xampp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10b239de54ba80fdd39de02bfe205abd212c403ced42e5d74e72abd43af23e56"
    $a1="4bc235380efd7ef2d94733b9b0003bd488d2eed8dc10c4c348c5fabbd475fdfd"
condition:
    ($a0 and $a1)
}