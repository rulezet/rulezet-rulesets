rule mysql41_hashed_default_creds_rapid7_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rapid7_inc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*04B526A6E1D85A827F4BEA9D42D8D3AB36C22DC8"
    $a1="*04B526A6E1D85A827F4BEA9D42D8D3AB36C22DC8"
condition:
    ($a0 and $a1)
}