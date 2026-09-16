rule sha384_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1b97e4e99e5007c4da5bc1690210ea7d2b3ff152db36b4d338d69e8b9269633df886b1f49e159f7d3386242fec82c3a4"
    $a1="1b97e4e99e5007c4da5bc1690210ea7d2b3ff152db36b4d338d69e8b9269633df886b1f49e159f7d3386242fec82c3a4"
condition:
    ($a0 and $a1)
}