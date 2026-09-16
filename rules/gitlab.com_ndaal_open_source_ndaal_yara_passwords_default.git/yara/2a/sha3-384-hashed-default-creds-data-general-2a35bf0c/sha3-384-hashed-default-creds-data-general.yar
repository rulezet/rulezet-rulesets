rule sha3_384_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
    $a1="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
    $a2="104ad37e1d492c4e6562d8365c129085b493e15ec4146b8ed3c64627a10250d4ad1c5f8200450170da2bba0f0f756270"
    $a3="104ad37e1d492c4e6562d8365c129085b493e15ec4146b8ed3c64627a10250d4ad1c5f8200450170da2bba0f0f756270"
    $a4="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
    $a5="104ad37e1d492c4e6562d8365c129085b493e15ec4146b8ed3c64627a10250d4ad1c5f8200450170da2bba0f0f756270"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}