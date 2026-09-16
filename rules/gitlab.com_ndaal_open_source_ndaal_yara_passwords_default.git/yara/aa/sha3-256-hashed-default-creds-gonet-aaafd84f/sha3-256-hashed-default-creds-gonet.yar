rule sha3_256_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfeb3a14a2b4d4796b2fdc5cb3eb0ba16a24a19d11df4316bf62125349e89cd4"
    $a1="f1dcd042f3c4ec914ac7618e514cca24f5a1854abfb282f455e268ae30d09264"
condition:
    ($a0 and $a1)
}