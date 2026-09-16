rule nthash_hashed_default_creds_ihoi
{
    meta:
        id = "7k407utmp4FEpFkgZZffka"
        fingerprint = "919170cf880d635ab5938f88ec5eab2619f197e5cbb3618dec4260e5e7c58a7b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ihoi."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="78641b253cb3b945040bcbaea5612f3f"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}