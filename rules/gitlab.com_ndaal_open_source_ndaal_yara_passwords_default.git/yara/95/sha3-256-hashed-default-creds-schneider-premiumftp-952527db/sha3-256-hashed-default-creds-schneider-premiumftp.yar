rule sha3_256_hashed_default_creds_schneider_premiumftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_premiumftp."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fec3572a226527ba9a636836222a7231362a9f348b1a4caf2cbfef230a703aea"
    $a1="ee372019b48bff763cdab6b666d63d413b6bab26429d03f66406dbef07b978d8"
condition:
    ($a0 and $a1)
}