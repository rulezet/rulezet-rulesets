rule sha256_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40c7aa75d0a355a0a77bb75a29e2fbc394e2333ae0f8b87d5b6af6ddaef9d183"
    $a1="a18603086e5bdf9df88ccc9f5a083fed093e819976e87456b74dafcbd7011114"
condition:
    ($a0 and $a1)
}