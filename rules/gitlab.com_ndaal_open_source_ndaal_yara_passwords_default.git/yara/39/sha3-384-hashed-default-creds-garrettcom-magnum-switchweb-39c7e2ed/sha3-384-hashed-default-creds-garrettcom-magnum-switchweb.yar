rule sha3_384_hashed_default_creds_garrettcom_magnum_switchweb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for garrettcom_magnum_switchweb."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
    $a1="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
condition:
    ($a0 and $a1)
}