rule sha224_hashed_default_creds_kronos
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kronos."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab2e5363e690c6b8d7872a4591f84318c43edc993bbd3377e0cf7a22"
    $a1="a4f4c656275be4ee922edc76733e8a8cfc1a663cbe290c8c8df801a3"
condition:
    ($a0 and $a1)
}