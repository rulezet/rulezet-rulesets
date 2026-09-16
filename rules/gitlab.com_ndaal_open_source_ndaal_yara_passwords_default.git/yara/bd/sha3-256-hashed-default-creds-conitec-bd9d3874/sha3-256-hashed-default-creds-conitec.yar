rule sha3_256_hashed_default_creds_conitec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conitec."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d0d724fdb69c8554c06d391ec7e34fd748e818803fb3b14d8d5cec73e099355"
    $a1="e403f044b9763e9befb491e795b12508b9a4786ae14b15edaf4148694269c79c"
condition:
    ($a0 and $a1)
}