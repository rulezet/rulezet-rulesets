rule sha224_hashed_default_creds_hyperic_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hyperic_inc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b16d3cf31a6f3f94d841009629a128c1c4e534b81879ff796e197d9c"
    $a1="b16d3cf31a6f3f94d841009629a128c1c4e534b81879ff796e197d9c"
condition:
    ($a0 and $a1)
}