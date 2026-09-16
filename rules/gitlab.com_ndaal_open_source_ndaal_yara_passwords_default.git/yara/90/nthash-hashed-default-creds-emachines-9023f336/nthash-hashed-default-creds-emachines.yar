rule nthash_hashed_default_creds_emachines
{
    meta:
        id = "1trGeGEZw91jKQbNvTtrbu"
        fingerprint = "5196d2d55f352abc4c8444fd105e1dd32ed526deb2d6acef914172283179d3e8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a84d93ab4e65b1b051ec624bca3c6096"
    $a1="90c6636db0d310f5f82ccc19ec04979d"
condition:
    ($a0 and $a1)
}