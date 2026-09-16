rule sha512_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e8bb8235e4bddb3f0de834507d50bc731578547a5dc0b18320bd0becca2b3939d7f14db19066c6393b6328be9ccdc558223c23213887dbd0c8be76ba909915f"
    $a1="880a2c02839be9d25ad8f43dfda082deccad74166f4c1407900650c316f2aeedda3718abcc23ea01a44c065a37b892ff9c6ab7cc5baa8e601167abaef7d6236b"
condition:
    ($a0 and $a1)
}