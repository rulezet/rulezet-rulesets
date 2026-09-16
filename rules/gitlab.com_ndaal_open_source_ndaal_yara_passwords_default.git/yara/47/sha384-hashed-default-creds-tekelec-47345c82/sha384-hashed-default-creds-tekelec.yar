rule sha384_hashed_default_creds_tekelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tekelec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9f8866402e5d88a92d7164f4ab16ccc48ceebcd9e204d22414f0d124b5b81fa51313c38dedfb37cab53b3bc2ba644eb"
    $a1="e9f8866402e5d88a92d7164f4ab16ccc48ceebcd9e204d22414f0d124b5b81fa51313c38dedfb37cab53b3bc2ba644eb"
condition:
    ($a0 and $a1)
}