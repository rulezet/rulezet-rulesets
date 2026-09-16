rule blake2b_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a14280a57284b16718c10ba0a699ab2b30c2d32b3dbff62d08c31627c1ec61b6d81d12a6c21806b1e47718af7321bd7d7019d96b8e5f55ec7ab5a7db1b8dbe6f"
    $a1="bdc242cf50e30b58e26c2d8167cd1c3a3cc9b6caf11d44767e77f3f74bad3ab9dbbd2b8ab496ee34ccca381db17c80dd30b38701fdf2e3ebb106afcabc85e260"
condition:
    ($a0 and $a1)
}