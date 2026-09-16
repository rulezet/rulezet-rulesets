rule nthash_hashed_default_creds_netbotz
{
    meta:
        id = "7k4nw3NyTipo33aJVANU2o"
        fingerprint = "d3c70ff8508ee355f3d418b35a22b8f58228669402f3a3806916c6602663bcd2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d965caef1b124adeddaa40dce50e6f9b"
    $a1="d965caef1b124adeddaa40dce50e6f9b"
condition:
    ($a0 and $a1)
}