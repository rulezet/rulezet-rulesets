rule sha384_hashed_default_creds_atlassian_confluence
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian_confluence."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13769de450dd148d451124e573e9298a65febf09eaae1e92d3312199a5004dc25e7d00f4b5c004d7b77a9dc3aed830cb"
    $a1="08ba31f8136306bf50bcdd88a5b013c15b100fedd1f03c6d75feac78dec2e50c6cc58f8ea1a884cb74a093c5c11ff836"
condition:
    ($a0 and $a1)
}