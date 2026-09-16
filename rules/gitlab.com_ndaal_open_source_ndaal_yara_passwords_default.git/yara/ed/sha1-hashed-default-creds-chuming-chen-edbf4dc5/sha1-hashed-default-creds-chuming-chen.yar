rule sha1_hashed_default_creds_chuming_chen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for chuming_chen."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74913f5cd5f61ec0bcfdb775414c2fb3d161b620"
    $a1="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
condition:
    ($a0 and $a1)
}