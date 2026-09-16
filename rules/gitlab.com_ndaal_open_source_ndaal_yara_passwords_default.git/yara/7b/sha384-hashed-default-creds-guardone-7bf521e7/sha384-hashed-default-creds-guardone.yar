rule sha384_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6df6203da3bc5d7ee3c31d4cfb2a625381b677c7966268314a2dbe00fe400464a359f9bf7d2ccfd1aecaca2b4b3412a4"
    $a1="183c8b5575ad115092768178d8f3d3c98c54d01504662bbb5381f74105d2ecb82e8dae6254a4cbc2b78688dc03b77484"
condition:
    ($a0 and $a1)
}