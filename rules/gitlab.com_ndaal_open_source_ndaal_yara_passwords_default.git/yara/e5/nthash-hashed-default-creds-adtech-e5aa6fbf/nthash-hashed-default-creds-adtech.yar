rule nthash_hashed_default_creds_adtech
{
    meta:
        id = "1soiRVXdli5wl9b88S7jh4"
        fingerprint = "c0d57f83667058b4631783428e3659facddc25620105d246f6bdf527786f04ea"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adtech."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f362720b9972dbe1c222b7355643bb61"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}