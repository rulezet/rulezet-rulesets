rule sha256_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3edec2353f5f1af480be3f5d3f66fe1035c422a32a9cbbfd74db8f9b99d93c88"
    $a1="1583c983c31d27b99e8ee57e9bb98fa2e6acf542664d0951c5edeabe0c751f01"
condition:
    ($a0 and $a1)
}