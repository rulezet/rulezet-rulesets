rule sha3_512_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58857c71301907ac4669cf8f78d4c07e570e2e8257740d08ad7f5426a999546d54a1696ad6d70988982d840b4c78dd750f212c4dfd495e0a2ea2234359d3720a"
    $a1="c9fbb6fa8c4f01007aff7d72821cc14c4e4ee104f4d45ce27775279bdbb39e6bb1bd5b9e2984c08674541271398f1087e749138f3a9d47a20ffa480996d0e2cc"
condition:
    ($a0 and $a1)
}