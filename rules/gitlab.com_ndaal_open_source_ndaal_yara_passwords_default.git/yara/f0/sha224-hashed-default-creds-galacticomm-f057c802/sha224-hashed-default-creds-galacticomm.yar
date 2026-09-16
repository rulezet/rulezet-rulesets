rule sha224_hashed_default_creds_galacticomm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for galacticomm."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91e7c34a031434f5dc7e1fff0e8e175987899d54d8d7505ba26d3896"
    $a1="91e7c34a031434f5dc7e1fff0e8e175987899d54d8d7505ba26d3896"
condition:
    ($a0 and $a1)
}