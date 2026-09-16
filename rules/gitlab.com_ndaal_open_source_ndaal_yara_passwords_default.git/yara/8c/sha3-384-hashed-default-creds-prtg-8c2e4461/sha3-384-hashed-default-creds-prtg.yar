rule sha3_384_hashed_default_creds_prtg
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for prtg."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0e75988d6eee6fd1e529c86165650f0edc92fb78a61427cab228cbe043ecc993a1f0e56ae9929a737831bb797677b224"
    $a1="0e75988d6eee6fd1e529c86165650f0edc92fb78a61427cab228cbe043ecc993a1f0e56ae9929a737831bb797677b224"
condition:
    ($a0 and $a1)
}