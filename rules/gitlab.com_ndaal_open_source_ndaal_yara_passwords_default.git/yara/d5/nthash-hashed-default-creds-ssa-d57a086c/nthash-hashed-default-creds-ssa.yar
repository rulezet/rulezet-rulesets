rule nthash_hashed_default_creds_ssa
{
    meta:
        id = "1DwgVBZ6YtskafkqKq6GoK"
        fingerprint = "e6662b99425688a714b0c7e8d5701cf5467c9792fbeacaae0dd4097108018d74"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dca72a6547c6d2321950afe9b0daf41"
    $a1="8dca72a6547c6d2321950afe9b0daf41"
condition:
    ($a0 and $a1)
}