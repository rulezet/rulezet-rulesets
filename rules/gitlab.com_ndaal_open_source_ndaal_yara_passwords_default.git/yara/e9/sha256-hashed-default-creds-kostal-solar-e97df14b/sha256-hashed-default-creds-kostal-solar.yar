rule sha256_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e452b7ec586a404ef1b3099e5fa3c6f91f6d62cea0c3cde060e171ce1771e1a"
    $a1="f751c7bd7329bc2e7a2a98b6399405c009268135f4b50b6e12ff34e99d6dc52f"
condition:
    ($a0 and $a1)
}