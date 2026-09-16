rule nthash_hashed_default_creds_cisco_ssh
{
    meta:
        id = "2WNGGqwL4rOKlYUZVhWucI"
        fingerprint = "ddf98087bfe83fd62d1a38cd9a81d2a2f6427538838da3549369d5d177ea9be4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c800f13a3ce86ed2540dd4e7331e9a2"
    $a1="5c800f13a3ce86ed2540dd4e7331e9a2"
    $a2="5c800f13a3ce86ed2540dd4e7331e9a2"
    $a3="f228a3a3c4f734aa12449e2bfc0a652e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}