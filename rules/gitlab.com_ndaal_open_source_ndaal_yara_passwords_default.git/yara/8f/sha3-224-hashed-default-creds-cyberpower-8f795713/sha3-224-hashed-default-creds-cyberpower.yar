rule sha3_224_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3fe56cfe02acf5ab50c18bc677a33685d0e25898d684fe26df279cdf"
    $a1="3fe56cfe02acf5ab50c18bc677a33685d0e25898d684fe26df279cdf"
    $a2="3fe56cfe02acf5ab50c18bc677a33685d0e25898d684fe26df279cdf"
    $a3="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}