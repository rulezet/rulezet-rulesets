rule nthash_hashed_default_creds_mx_linux
{
    meta:
        id = "3Y9YgfIFXKh9xn1547vpmt"
        fingerprint = "520c7d35537cda98eb7f65664c80dbc3618f780af129b0d1fb1de62e4a34523b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="527c9c819b286efb8ec4ebb5b5ae71cf"
    $a1="527c9c819b286efb8ec4ebb5b5ae71cf"
    $a2="329153f560eb329c0e1deea55e88a1e9"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="728a3edf824a80c984648faaf762e7ce"
    $a5="2e584618c0c086af05ace5bbd6465cc7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}