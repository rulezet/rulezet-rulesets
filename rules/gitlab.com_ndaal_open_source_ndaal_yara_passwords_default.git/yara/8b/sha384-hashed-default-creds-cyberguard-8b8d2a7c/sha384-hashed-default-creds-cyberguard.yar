rule sha384_hashed_default_creds_cyberguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberguard."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="791dc4ce6a74829f9d76b2675e04c10b2fee20a60d2ac4ee302fc410107cc36f4690a39dd05b15a42c7f9b0b84ea720d"
    $a1="791dc4ce6a74829f9d76b2675e04c10b2fee20a60d2ac4ee302fc410107cc36f4690a39dd05b15a42c7f9b0b84ea720d"
condition:
    ($a0 and $a1)
}