rule nthash_hashed_default_creds_tandem
{
    meta:
        id = "EWebKu519d1Sin2bpWRDt"
        fingerprint = "d67c5efa8fdb6733e0c14c50821e8554d71649bff39b3184c92c7b94796d5ee4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d3986e540a63647454a50e26477ef94"
    $a1="568518ec5cdf396aa685ae7099108322"
condition:
    ($a0 and $a1)
}