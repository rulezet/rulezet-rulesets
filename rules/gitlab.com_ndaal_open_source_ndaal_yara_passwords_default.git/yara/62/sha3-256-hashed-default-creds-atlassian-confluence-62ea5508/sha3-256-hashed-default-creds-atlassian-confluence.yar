rule sha3_256_hashed_default_creds_atlassian_confluence
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian_confluence."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2cb56e1fbfb432f9096c4382352d2858e3d8a3c42afb72a71cc5f40b4d3dae3c"
    $a1="ddc3a96a673f010f8231008d2df546d710b87ab0308f0da683a82ac621cda367"
condition:
    ($a0 and $a1)
}