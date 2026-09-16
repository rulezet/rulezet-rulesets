rule sha1_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9153587bc5c5e201f3e349a581f01fe0143b54c2"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="774cee9970f812928e97dbec8b46bd184d690dfd"
    $a3="774cee9970f812928e97dbec8b46bd184d690dfd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}