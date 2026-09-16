rule sha3_256_hashed_default_creds_phpreactor
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5813046cb52ca23bdb05915e6e5e7929f9af4fc2c1ab4ee466ecd20b1eda7d33"
    $a1="57760688d1f824db5d9c6bd4024622bda7c9550529d99c42cc890e881a285ac7"
condition:
    ($a0 and $a1)
}