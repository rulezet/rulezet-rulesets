rule sha3_384_hashed_default_creds_andover_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for andover_controls."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="227f41d812305a1e02c2991c283019bab3a5283c489a2b8d26becbcf81c7b33d3856a3816bf8ba2e9a9c1e4156fe5fd2"
    $a1="227f41d812305a1e02c2991c283019bab3a5283c489a2b8d26becbcf81c7b33d3856a3816bf8ba2e9a9c1e4156fe5fd2"
condition:
    ($a0 and $a1)
}