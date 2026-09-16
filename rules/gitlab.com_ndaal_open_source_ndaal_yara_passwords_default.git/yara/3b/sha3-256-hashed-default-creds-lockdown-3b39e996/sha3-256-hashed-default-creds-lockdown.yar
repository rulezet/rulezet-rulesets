rule sha3_256_hashed_default_creds_lockdown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lockdown."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91bd5da2e6d20943460748fdc99559a82e55b6ffa1ac9d6f562b2026c3777f3b"
    $a1="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
condition:
    ($a0 and $a1)
}