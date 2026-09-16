rule blake2b_hashed_default_creds_andover_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for andover_controls."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5210a3baf71239ceb36cb753f693c9257c34ae9bf1daf93ab4ff29a770725a1fb69d5ddf7e792076db1d2b0cf4f002fc3314d7d5711c671fa58114e361ff5e96"
    $a1="5210a3baf71239ceb36cb753f693c9257c34ae9bf1daf93ab4ff29a770725a1fb69d5ddf7e792076db1d2b0cf4f002fc3314d7d5711c671fa58114e361ff5e96"
condition:
    ($a0 and $a1)
}