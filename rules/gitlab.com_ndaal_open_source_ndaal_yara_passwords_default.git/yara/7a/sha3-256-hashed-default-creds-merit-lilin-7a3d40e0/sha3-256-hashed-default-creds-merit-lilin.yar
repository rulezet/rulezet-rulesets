rule sha3_256_hashed_default_creds_merit_lilin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for merit_lilin."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b0d0648bc070eb63ce41edf68d3e1ccc586bcd4bce4dc255fe62ad4c0d05758"
    $a1="8a6251a248fe276a471cc70ef001015f6abe28296ad882bb09e57a115f1a1c89"
condition:
    ($a0 and $a1)
}