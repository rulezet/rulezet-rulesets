rule sha3_224_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="56a9602a1d3111b4a5c6c78e6210e0d431718b1a99315e78e232c27c"
    $a1="56a9602a1d3111b4a5c6c78e6210e0d431718b1a99315e78e232c27c"
condition:
    ($a0 and $a1)
}