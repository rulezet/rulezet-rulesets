rule sha3_384_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c55252fb45db32e4e921369d697a018eb47d8f11c98b3bc6889fcdc3818557d3c18469bddf61364e06b05b4524a67130"
    $a1="1bc849b02bffdc35def1bc15ff5d80246a34cc2f4ace9baacfbae2888c8f5abdc797b5a46b99dea75b34680cfbeae169"
condition:
    ($a0 and $a1)
}