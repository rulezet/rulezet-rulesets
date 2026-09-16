rule sha3_256_hashed_default_creds_memotec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for memotec."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90e6263244bbac7413c1947f2306e13af65ee6507c6d46e3493b276ecc098871"
    $a1="9fac138b2a4571e1571fed9f2f6177c455208b06e44fa7a42c34bbca13aaa399"
condition:
    ($a0 and $a1)
}