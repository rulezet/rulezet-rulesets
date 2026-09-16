rule sha512_hashed_default_creds_conitec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conitec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26ec02cf12f565c6c93be6f4d08afd9898657a5d33812b014e7dfa76baa560ddf0ad12a26de2bdb240c666b4b526d9d64ce139ee824657a2d9b52d257d69c996"
    $a1="ddb01697ab4b84763cf27b42324e6938946d41913e0e1181921d6b2c0e955218ef7ac25bef212de919724259e389fc12a7a49c93f2ce5d4b3e17d3c050fbc251"
condition:
    ($a0 and $a1)
}