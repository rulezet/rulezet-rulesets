rule md5_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2af209a360a2217e0838147bc405aeff"
    $a1="d6185f8c684d193324b1a5ac7c74522d"
    $a2="e3502ccb6f675cb6e339361b4aa2dbaf"
    $a3="09c531defdd28af54ed230c1fb8bff32"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}