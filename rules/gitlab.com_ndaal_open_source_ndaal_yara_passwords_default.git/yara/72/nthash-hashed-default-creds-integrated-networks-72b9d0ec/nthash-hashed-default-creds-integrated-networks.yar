rule nthash_hashed_default_creds_integrated_networks
{
    meta:
        id = "5Fhm0KGQMJuCqd6n2cw9bj"
        fingerprint = "42bda4633a8a93f95c3dfc2f8b9087189e6f32348603f3c2d146d155ee0945d9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for integrated_networks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="259745cb123a52aa2e693aaacca2db52"
    $a3="d144986c6122b1b1654ba39932465528"
    $a4="7a70763ef136e721edf5ee6f46098367"
    $a5="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}