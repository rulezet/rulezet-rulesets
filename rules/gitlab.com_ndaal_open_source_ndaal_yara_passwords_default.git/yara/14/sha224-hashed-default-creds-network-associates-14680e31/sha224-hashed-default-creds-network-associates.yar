rule sha224_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e3ee31716ea3ec3ff9de7ead99504b8edaff7b43b164d97cb5c3ff4"
    $a1="11ea23d09b816a812427c1a4dc9bcdc1badb7190d5f83f2f1c40a5de"
    $a2="b41b098fb9ea6c277a4225c6de84ea684c916057f546e18fa40a539f"
    $a3="62a1b357b1265caa6d47ede4ea5000c79b0f91d1c7a8aa966d4f2e22"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}