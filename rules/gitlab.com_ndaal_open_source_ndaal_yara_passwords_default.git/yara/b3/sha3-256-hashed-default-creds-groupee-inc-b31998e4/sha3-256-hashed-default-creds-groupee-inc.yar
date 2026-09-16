rule sha3_256_hashed_default_creds_groupee_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for groupee_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be66ee35e1792556c669b392bd7c601041eddc42c3aa73e4150c37a05a1bf782"
    $a1="34b13d6fbe184bd3b3c82c4eca056c9345636e642f407bc4cdf8268c702e773e"
condition:
    ($a0 and $a1)
}