rule sha224_hashed_default_creds_team_xodus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for team_xodus."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e357c0e270314c6b9b732e707420c67bb748295b4df16cc452bd77b"
    $a1="2e357c0e270314c6b9b732e707420c67bb748295b4df16cc452bd77b"
condition:
    ($a0 and $a1)
}