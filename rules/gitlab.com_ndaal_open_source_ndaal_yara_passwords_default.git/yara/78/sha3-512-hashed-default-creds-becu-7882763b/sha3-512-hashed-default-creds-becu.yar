rule sha3_512_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="910199c58fbb150603f4de110cb20e0f694a5744503421016fb7f90f95653f3c04d64d1250d76372558494214410537df2da2a9670bebb1c2435551b85cc30ce"
    $a1="e5b987007670291ebcc757270fa96b43976e24441a7b385fb408b5d072a9a5179555d3fe602526f3340bbf13c7ed322e457e3c2fb73739cbdbcba51b4ab8c379"
condition:
    ($a0 and $a1)
}