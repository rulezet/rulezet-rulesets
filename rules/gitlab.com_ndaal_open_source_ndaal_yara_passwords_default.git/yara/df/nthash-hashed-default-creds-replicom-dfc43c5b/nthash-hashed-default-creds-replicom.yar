rule nthash_hashed_default_creds_replicom
{
    meta:
        id = "5bpD9NCwDesfReix58ONb3"
        fingerprint = "808498bb860e1535d3f78d92080ad38583222dc036e9160edad623a7962f236a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for replicom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58e886970f0f2be088b03feba00bb8e5"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}