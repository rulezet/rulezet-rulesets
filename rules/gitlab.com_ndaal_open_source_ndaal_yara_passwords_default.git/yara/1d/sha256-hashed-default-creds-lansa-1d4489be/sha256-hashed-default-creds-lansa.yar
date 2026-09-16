rule sha256_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="ef260e9aa3c673af240d17a2660480361a8e081d1ffeca2a5ed0e3219fc18567"
    $a3="ef260e9aa3c673af240d17a2660480361a8e081d1ffeca2a5ed0e3219fc18567"
    $a4="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a5="26f49ff6129642d662f97700fdd00f6e5434ef94859f97e20a4dec2cf1311059"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}