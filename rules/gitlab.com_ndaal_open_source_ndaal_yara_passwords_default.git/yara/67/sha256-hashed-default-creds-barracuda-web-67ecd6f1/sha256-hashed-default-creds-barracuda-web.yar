rule sha256_hashed_default_creds_barracuda_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barracuda_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="5fee6a563b380a9e5fcaec6ecfdfa86692dbdeb4c0ad2bc6980a3a6c4e0f4f7b"
    $a3="5fee6a563b380a9e5fcaec6ecfdfa86692dbdeb4c0ad2bc6980a3a6c4e0f4f7b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}