rule sha224_hashed_default_creds_redhat
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d3f8410c9f2e6a566d268d16363743e6f37dd421cd3c369632408bcf"
    $a1="d3f8410c9f2e6a566d268d16363743e6f37dd421cd3c369632408bcf"
    $a2="8acd70840f1928a2a80c548d7599a07e752a6804612469d1dabac68a"
    $a3="d3f8410c9f2e6a566d268d16363743e6f37dd421cd3c369632408bcf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}