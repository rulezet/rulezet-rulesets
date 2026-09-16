rule sha256_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c1aaeeab26f30bd0de1ecd863850247067c475a6c5aeb707cedb8ba9db04ae8"
    $a1="9c9064c59f1ffa2e174ee754d2979be80dd30db552ec03e7e327e9b1a4bd594e"
condition:
    ($a0 and $a1)
}