rule sha3_256_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a15b810619da2116e404d84e3ce40c3e7ab3b2165b1ecebc033d7fb314d0ee44"
    $a1="509260e47b66dbeb5b473f62fa7834f89ad3dffba17c34da26c0e06eade2f882"
condition:
    ($a0 and $a1)
}