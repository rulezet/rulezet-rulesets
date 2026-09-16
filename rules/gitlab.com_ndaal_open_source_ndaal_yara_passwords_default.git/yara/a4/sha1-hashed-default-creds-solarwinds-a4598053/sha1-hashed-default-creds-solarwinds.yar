rule sha1_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4395dfa6b49ad83e507268e10cde99a27c76f085"
    $a1="9678e54620f8db82406b94fa0c82b187c136c54a"
    $a2="f01d972ce50c9fc9ee69e5feb87aed03a9c70202"
    $a3="f01d972ce50c9fc9ee69e5feb87aed03a9c70202"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}