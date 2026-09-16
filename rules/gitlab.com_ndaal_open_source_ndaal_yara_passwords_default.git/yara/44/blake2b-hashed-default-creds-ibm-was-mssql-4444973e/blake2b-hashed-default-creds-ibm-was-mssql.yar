rule blake2b_hashed_default_creds_ibm_was_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_was_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6effacaf73c1e23f1ea52c5ccc0946a6c95cd1ff5968cc2216fc3967541a3ac8d3e5707e2477a8f6c55958ed904361e409037695b5467b1c2582ac58c80fdc47"
    $a1="6effacaf73c1e23f1ea52c5ccc0946a6c95cd1ff5968cc2216fc3967541a3ac8d3e5707e2477a8f6c55958ed904361e409037695b5467b1c2582ac58c80fdc47"
condition:
    ($a0 and $a1)
}