rule nthash_hashed_default_creds_integral
{
    meta:
        id = "2bN3wgGqylbZrbmcAYmba1"
        fingerprint = "f89d69bca691f1718394610ad4c084a5260e2f670c70e7022b12ef89dbce4a5e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for integral."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="becedb42ec3c5c7f965255338be4453c"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}